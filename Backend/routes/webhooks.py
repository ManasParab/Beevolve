"""Razorpay asynchronous webhook verification, deduplication, and PostgreSQL dispatch routes."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
import psycopg
from psycopg.errors import NoDataFound

from config import settings
from database import open_connection

router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])
logger = logging.getLogger(__name__)


def epoch_to_dt(value: int | str | None) -> datetime | None:
    """Convert Razorpay epoch seconds into a UTC-aware datetime."""
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc)


def dispatch_event(conn: psycopg.Connection, event_type: str, payload: dict[str, Any]) -> None:
    """Apply a verified Razorpay webhook event directly against PostgreSQL functions and tables."""
    payment = payload.get("payload", {}).get("payment", {}).get("entity", {})
    subscription = payload.get("payload", {}).get("subscription", {}).get("entity", {})

    if event_type == "payment.captured":
        provider_order_id = payment.get("order_id")
        payment_id = payment.get("id")
        if not provider_order_id or not payment_id:
            raise RuntimeError("Captured payment is missing its IDs")

        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT public.apply_payment_success(
                          %s::text, %s::text, %s::text, %s::integer, %s::boolean
                        )
                        """,
                        (
                            provider_order_id,
                            payment_id,
                            payment.get("method"),
                            int(payment.get("amount", 0)),
                            False,
                        ),
                    )
        except NoDataFound:
            # Autopay payments arrive without a pre-existing checkout order row and are handled by subscription.charged.
            logger.info("Captured payment belongs to an autopay flow: %s", payment_id)
            return

    elif event_type == "payment.authorized":
        provider_order_id = payment.get("order_id")
        if not provider_order_id:
            raise RuntimeError("Authorized payment has no order ID")

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.orders
                   SET payment_status = 'submitted'
                 WHERE provider_order_id = %s
                   AND order_status = 'pending'
                """,
                (provider_order_id,),
            )

    elif event_type == "payment.failed":
        provider_order_id = payment.get("order_id")
        if provider_order_id:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT public.apply_payment_failure(%s::text)",
                    (provider_order_id,),
                )

    elif event_type == "subscription.charged":
        notes = subscription.get("notes") or {}
        order_id = notes.get("order_id")
        payment_id = payment.get("id")
        if not order_id or not payment_id or not subscription.get("id"):
            raise RuntimeError("Subscription charge is missing required IDs or order notes")

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT public.apply_subscription_charged(
                  %s::uuid, %s::text, %s::text, %s::text, %s::integer,
                  %s::timestamptz, %s::timestamptz, %s::timestamptz, %s::text
                )
                """,
                (
                    order_id,
                    subscription["id"],
                    payment_id,
                    payment.get("order_id"),
                    int(payment.get("amount", 0)),
                    epoch_to_dt(payment.get("created_at")),
                    epoch_to_dt(subscription.get("current_end")),
                    epoch_to_dt(subscription.get("charge_at")),
                    payment.get("method"),
                ),
            )

    elif event_type in {
        "subscription.authenticated",
        "subscription.activated",
        "subscription.pending",
        "subscription.halted",
        "subscription.cancelled",
        "subscription.completed",
    }:
        subscription_id = subscription.get("id")
        if not subscription_id:
            raise RuntimeError("Subscription event is missing its ID")

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT public.apply_subscription_status(
                  %s::text, %s::text, %s::timestamptz
                )
                """,
                (
                    subscription_id,
                    subscription.get("status"),
                    epoch_to_dt(subscription.get("charge_at")),
                ),
            )


@router.post("/razorpay")
async def razorpay_webhook(request: Request):
    """Verify Razorpay webhook signature, deduplicate in PostgreSQL, and process event."""
    if not settings.razorpay_webhook_secret:
        logger.error("RAZORPAY_WEBHOOK_SECRET is not configured")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook configuration is missing",
        )

    raw_body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature")
    event_id = request.headers.get("X-Razorpay-Event-Id")

    if not signature or not event_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Razorpay webhook headers",
        )

    expected_signature = hmac.new(
        settings.razorpay_webhook_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook signature",
        )

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        ) from exc

    event_type = payload.get("event")
    if not event_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing event type",
        )

    conn = open_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public.register_webhook_event(%s::text, %s::text, %s::jsonb) AS registered",
                (event_id, event_type, json.dumps(payload)),
            )
            reg_row = cur.fetchone()
        conn.commit()

        if not reg_row or reg_row["registered"] is not True:
            return {"status": "duplicate"}

        try:
            dispatch_event(conn, event_type, payload)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE public.webhook_events
                       SET processed_at = %s
                     WHERE event_id = %s
                    """,
                    (datetime.now(timezone.utc), event_id),
                )
            conn.commit()
        except Exception as exc:
            logger.exception("Webhook processing failed for event %s (%s)", event_id, event_type)
            if not conn.closed:
                conn.rollback()
            # Remove deduplication entry so Razorpay can retry the event.
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM public.webhook_events WHERE event_id = %s",
                        (event_id,),
                    )
                conn.commit()
            except Exception:
                logger.exception("Could not reset failed webhook event %s", event_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Webhook processing failed",
            ) from exc
    finally:
        if not conn.closed:
            conn.close()

    return {"status": "processed"}
