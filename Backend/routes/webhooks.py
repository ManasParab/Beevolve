# This file will handle Razorpay events that arrive asynchronously, including:
# - payment.captured
# - payment.failed
# - Subscription activation, cancellation and charge events
# It must verify the Razorpay webhook signature using the configured webhook secret. It should call the database function register_webhook_event to prevent duplicate processing, then dispatch the event to the appropriate payment/subscription database function.
# For example, successful one-time payments should use apply_payment_success; failed payments should use apply_payment_failure.
# Important: Your latest ZIP doesn’t include the earlier RazorpaySandbox reference folder. We should not pretend we copied its webhook code. We’ll implement this file against your current SQL schema and verify it with test events before configuring the live webhook URL.


import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from supabase_client import supabase_rest_request, supabase_rpc

router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])
logger = logging.getLogger(__name__)

RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")


def epoch_to_iso(value):
    """Convert Razorpay epoch seconds into a UTC timestamp."""
    if value is None:
        return None

    return datetime.fromtimestamp(
        int(value), tz=timezone.utc
    ).isoformat()


def check_response(response, message):
    if response.status_code >= 400:
        logger.error(
            "%s: %s %s",
            message,
            response.status_code,
            response.text,
        )
        raise RuntimeError(message)

    try:
        return response.json()
    except Exception:
        return None


async def mark_event_processed(event_id):
    response = await supabase_rest_request(
        "PATCH",
        "webhook_events",
        params={"event_id": f"eq.{event_id}"},
        json={"processed_at": datetime.now(timezone.utc).isoformat()},
        extra_headers={"Prefer": "return=minimal"},
    )
    check_response(response, "Could not mark webhook as processed")


async def remove_event_for_retry(event_id):
    response = await supabase_rest_request(
        "DELETE",
        "webhook_events",
        params={"event_id": f"eq.{event_id}"},
        extra_headers={"Prefer": "return=minimal"},
    )
    check_response(response, "Could not reset webhook event")


async def dispatch_event(event_type, payload):
    payment = (
        payload.get("payload", {})
        .get("payment", {})
        .get("entity", {})
    )

    subscription = (
        payload.get("payload", {})
        .get("subscription", {})
        .get("entity", {})
    )

    if event_type == "payment.captured":
        provider_order_id = payment.get("order_id")
        payment_id = payment.get("id")

        if not provider_order_id or not payment_id:
            raise RuntimeError("Captured payment is missing its IDs")

        response = await supabase_rpc(
            "apply_payment_success",
            {
                "p_provider_order_id": provider_order_id,
                "p_provider_payment_id": payment_id,
                "p_payment_mode": payment.get("method"),
                "p_amount": int(payment.get("amount", 0)),
                "p_signature_verified": False,
            },
        )

        # Autopay payments are handled by subscription.charged.
        if (
            response.status_code >= 400
            and "ORDER_NOT_FOUND" in response.text
        ):
            logger.info(
                "Captured payment belongs to an autopay flow: %s",
                payment_id,
            )
            return

        check_response(response, "Could not record captured payment")

    elif event_type == "payment.authorized":
        provider_order_id = payment.get("order_id")

        if not provider_order_id:
            raise RuntimeError("Authorized payment has no order ID")

        response = await supabase_rest_request(
            "PATCH",
            "orders",
            params={
                "provider_order_id": f"eq.{provider_order_id}",
                "order_status": "eq.pending",
            },
            json={"payment_status": "submitted"},
            extra_headers={"Prefer": "return=minimal"},
        )
        check_response(response, "Could not update authorized payment")

    elif event_type == "payment.failed":
        provider_order_id = payment.get("order_id")

        if provider_order_id:
            response = await supabase_rpc(
                "apply_payment_failure",
                {"p_provider_order_id": provider_order_id},
            )
            check_response(response, "Could not record failed payment")

    elif event_type == "subscription.charged":
        notes = subscription.get("notes") or {}
        order_id = notes.get("order_id")
        payment_id = payment.get("id")

        if not order_id or not payment_id or not subscription.get("id"):
            raise RuntimeError(
                "Subscription charge is missing required IDs or order notes"
            )

        response = await supabase_rpc(
            "apply_subscription_charged",
            {
                "p_order_id": order_id,
                "p_provider_subscription_id": subscription["id"],
                "p_provider_payment_id": payment_id,
                "p_provider_order_id": payment.get("order_id"),
                "p_amount": int(payment.get("amount", 0)),
                "p_paid_at": epoch_to_iso(payment.get("created_at")),
                "p_current_end": epoch_to_iso(subscription.get("current_end")),
                "p_charge_at": epoch_to_iso(subscription.get("charge_at")),
                "p_payment_method": payment.get("method"),
            },
        )
        check_response(response, "Could not record subscription charge")

    elif event_type.startswith("subscription."):
        subscription_id = subscription.get("id")

        if not subscription_id:
            raise RuntimeError("Subscription event is missing its ID")

        if event_type in {
            "subscription.authenticated",
            "subscription.activated",
            "subscription.pending",
            "subscription.halted",
            "subscription.cancelled",
            "subscription.completed",
        }:
            response = await supabase_rpc(
                "apply_subscription_status",
                {
                    "p_provider_subscription_id": subscription_id,
                    "p_provider_status": subscription.get("status"),
                    "p_charge_at": epoch_to_iso(
                        subscription.get("charge_at")
                    ),
                },
            )
            check_response(response, "Could not update subscription status")


@router.post("/razorpay")
async def razorpay_webhook(request: Request):
    if not RAZORPAY_WEBHOOK_SECRET:
        logger.error("RAZORPAY_WEBHOOK_SECRET is not configured")
        raise HTTPException(
            status_code=500,
            detail="Webhook configuration is missing",
        )

    raw_body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature")
    event_id = request.headers.get("X-Razorpay-Event-Id")

    if not signature or not event_id:
        raise HTTPException(
            status_code=400,
            detail="Missing Razorpay webhook headers",
        )

    expected_signature = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = payload.get("event")

    if not event_type:
        raise HTTPException(status_code=400, detail="Missing event type")

    registration = await supabase_rpc(
        "register_webhook_event",
        {
            "p_event_id": event_id,
            "p_event_type": event_type,
            "p_payload": payload,
        },
    )
    registered = check_response(
        registration, "Could not register webhook event"
    )

    # Supabase may return the boolean directly or inside a one-row result.
    if isinstance(registered, list) and registered:
        registered = next(iter(registered[0].values()))

    if registered is not True:
        return {"status": "duplicate"}

    try:
        await dispatch_event(event_type, payload)
        await mark_event_processed(event_id)
    except Exception:
        logger.exception(
            "Webhook processing failed for event %s (%s)",
            event_id,
            event_type,
        )

        # Remove the deduplication entry so Razorpay can retry the event.
        try:
            await remove_event_for_retry(event_id)
        except Exception:
            logger.exception("Could not reset failed webhook event %s", event_id)

        raise HTTPException(
            status_code=500,
            detail="Webhook processing failed",
        )

    return {"status": "processed"}

# Before we test it
# Two important checks remain:
#- Your .env must contain RAZORPAY_WEBHOOK_SECRET with the webhook secret configured in Razorpay. It is different from RAZORPAY_KEY_SECRET.
# - The code expects webhook_events.processed_at to exist. We need to verify that column before testing, and then register this router in main.py.