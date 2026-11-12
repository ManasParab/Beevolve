"""Recurring subscription creation, user subscription listing, and access check routes backed by PostgreSQL."""

from datetime import datetime, timezone
import logging
import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
import psycopg
from pydantic import BaseModel
import razorpay

from config import settings
from database import get_db
from routes.auth import get_current_user_id

router = APIRouter(prefix="/api/subscriptions", tags=["Subscriptions"])
logger = logging.getLogger(__name__)

client = (
    razorpay.Client(auth=(settings.razorpay_key_id, settings.razorpay_key_secret))
    if settings.razorpay_key_id and settings.razorpay_key_secret
    else None
)


class SubscriptionRequest(BaseModel):
    plan_id: str | None = None
    service: str | None = None


def _parse_optional_uuid(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    try:
        return str(UUID(raw_value.strip()))
    except ValueError:
        return None


@router.get("/plans")
def list_active_plans(conn: psycopg.Connection = Depends(get_db)):
    """Return active service plans and live pricing directly from PostgreSQL."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT pl.id AS plan_id,
                   pl.product_id,
                   pr.slug,
                   pr.name,
                   pr.category,
                   pl.plan_interval,
                   pl.duration_days,
                   pl.amount AS amount_paise,
                   pl.currency,
                   pl.provider_plan_id
              FROM public.mst_plan pl
              JOIN public.mst_product pr ON pr.id = pl.product_id
             WHERE pl.status = 'active'
               AND pr.status = 'active'
               AND pr.is_active = TRUE
             ORDER BY pl.created_date ASC
            """
        )
        rows = cur.fetchall()

    plans = []
    for row in rows:
        amount_paise = int(row["amount_paise"])
        amount_rupees = (
            amount_paise // 100
            if amount_paise % 100 == 0
            else round(amount_paise / 100, 2)
        )
        plans.append(
            {
                "plan_id": str(row["plan_id"]),
                "product_id": str(row["product_id"]),
                "slug": row["slug"],
                "name": row["name"],
                "category": row["category"],
                "plan_interval": row["plan_interval"],
                "duration_days": int(row["duration_days"]),
                "amount_paise": amount_paise,
                "amount_rupees": amount_rupees,
                "currency": row["currency"],
                "autopay_enabled": bool(row.get("provider_plan_id")),
            }
        )

    return {"plans": plans}


@router.post("/create")
def create_subscription(
    data: SubscriptionRequest,
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Create local order/order_items in PostgreSQL and start a Razorpay recurring subscription."""
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Razorpay is not configured.",
        )

    plan_uuid = _parse_optional_uuid(data.plan_id)
    service_name = (data.service or "").strip()
    if not plan_uuid and not service_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid plan_id or service name is required.",
        )

    plan = None
    with conn.cursor() as cur:
        if plan_uuid:
            cur.execute(
                """
                SELECT pl.id, pl.product_id, pl.amount, pl.currency,
                       pl.duration_days, pl.provider_plan_id
                  FROM public.mst_plan pl
                 WHERE pl.id = %s
                   AND pl.status = 'active'
                   AND pl.provider_plan_id IS NOT NULL
                 LIMIT 1
                """,
                (plan_uuid,),
            )
            plan = cur.fetchone()

        if not plan and service_name:
            cur.execute(
                """
                SELECT pl.id, pl.product_id, pl.amount, pl.currency,
                       pl.duration_days, pl.provider_plan_id
                  FROM public.mst_plan pl
                  JOIN public.mst_product pr ON pr.id = pl.product_id
                 WHERE LOWER(pr.name) = LOWER(%s)
                   AND pl.status = 'active'
                   AND pr.status = 'active'
                   AND pl.provider_plan_id IS NOT NULL
                 ORDER BY pl.created_date ASC
                 LIMIT 1
                """,
                (service_name,),
            )
            plan = cur.fetchone()

    if not plan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Plan not found or not configured for autopay.",
        )

    order_id = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.orders
              (id, user_id, payment_mode, payment_provider, amount, currency)
            VALUES (%s, %s, 'e-mandate', 'razorpay', %s, %s)
            """,
            (order_id, user_id, int(plan["amount"]), str(plan["currency"])),
        )
        cur.execute(
            """
            INSERT INTO public.order_items (order_id, plan_id, amount)
            VALUES (%s, %s, %s)
            """,
            (order_id, plan["id"], int(plan["amount"])),
        )
    conn.commit()

    try:
        subscription = client.subscription.create(
            {
                "plan_id": plan["provider_plan_id"],
                "customer_notify": 1,
                "total_count": 12,
                "notes": {
                    "order_id": order_id,
                },
            }
        )
    except Exception as exc:
        logger.exception("Razorpay subscription creation failed for order %s", order_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Unable to start the subscription. "
                "The local order may still exist; contact support before retrying."
            ),
        ) from exc

    return {
        "success": True,
        "order_id": order_id,
        "subscription_id": subscription.get("id"),
        "short_url": subscription.get("short_url"),
        "status": subscription.get("status"),
    }


@router.get("/me")
def get_my_subscriptions(
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Return the logged-in user's subscriptions joined with plan and product metadata."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.id, s.product_id, s.plan_id, s.order_id,
                   s.subscription_status, s.starts_at, s.expires_at,
                   s.auto_renew, s.provider_subscription_id,
                   s.auth_status, s.next_charge_at, s.created_date,
                   pl.plan_interval, pl.duration_days, pl.amount, pl.currency,
                   pr.slug AS product_slug, pr.name AS product_name,
                   pr.category AS product_category
              FROM public.subscriptions s
              JOIN public.mst_plan pl ON pl.id = s.plan_id
              JOIN public.mst_product pr ON pr.id = s.product_id
             WHERE s.user_id = %s
             ORDER BY s.created_date DESC
            """,
            (user_id,),
        )
        rows = cur.fetchall()

    subscriptions = []
    for row in rows:
        subscriptions.append(
            {
                "id": str(row["id"]),
                "product_id": str(row["product_id"]),
                "product_name": row["product_name"],
                "plan_id": str(row["plan_id"]),
                "order_id": str(row["order_id"]),
                "subscription_status": row["subscription_status"],
                "starts_at": row["starts_at"].isoformat() if row["starts_at"] else None,
                "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
                "auto_renew": bool(row["auto_renew"]),
                "provider_subscription_id": row["provider_subscription_id"],
                "auth_status": row["auth_status"],
                "next_charge_at": (
                    row["next_charge_at"].isoformat() if row["next_charge_at"] else None
                ),
                "created_date": (
                    row["created_date"].isoformat() if row["created_date"] else None
                ),
                "mst_plan": {
                    "plan_interval": row["plan_interval"],
                    "duration_days": row["duration_days"],
                    "amount": row["amount"],
                    "currency": row["currency"],
                    "mst_product": {
                        "id": str(row["product_id"]),
                        "slug": row["product_slug"],
                        "name": row["product_name"],
                        "category": row["product_category"],
                    },
                },
            }
        )

    return {"subscriptions": subscriptions}


@router.get("/access/{product_id}")
def check_product_access(
    product_id: UUID,
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Check whether the user currently holds an active non-expired subscription for product_id."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, subscription_status, starts_at, expires_at
              FROM public.subscriptions
             WHERE user_id = %s
               AND product_id = %s
               AND subscription_status = 'active'
               AND status = 'active'
            """,
            (user_id, str(product_id)),
        )
        records = cur.fetchall()

    now = datetime.now(timezone.utc)
    for record in records:
        starts_at = record.get("starts_at")
        expires_at = record.get("expires_at")
        if starts_at and starts_at > now:
            continue
        if expires_at and expires_at <= now:
            continue
        return {
            "has_access": True,
            "product_id": str(product_id),
            "message": "Access granted.",
        }

    return {
        "has_access": False,
        "product_id": str(product_id),
        "message": "An active purchase is required to access this service.",
    }
