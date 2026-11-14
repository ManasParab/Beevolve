"""Razorpay one-time checkout order creation and payment verification routes backed by PostgreSQL."""

from datetime import date
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
import _pg_bootstrap  # noqa: F401
import psycopg
from pydantic import BaseModel, Field
import razorpay

from config import settings
from database import get_db
from routes.auth import get_current_user_id

router = APIRouter(prefix="/api/payments", tags=["Payments"])
logger = logging.getLogger(__name__)

client = (
    razorpay.Client(auth=(settings.razorpay_key_id, settings.razorpay_key_secret))
    if settings.razorpay_key_id and settings.razorpay_key_secret
    else None
)


class PaymentVerification(BaseModel):
    razorpay_order_id: str = Field(min_length=1)
    razorpay_payment_id: str = Field(min_length=1)
    razorpay_signature: str = Field(min_length=1)


class OrderRequest(BaseModel):
    service: str = "Career Toolkit"
    coupon_code: str | None = None


def _as_date(value: date | str | None) -> date | None:
    if value is None:
        return None
    return value if isinstance(value, date) else date.fromisoformat(value)


@router.post("/create-order")
def create_order(
    data: OrderRequest,
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Create a Razorpay one-time order from PostgreSQL plan/coupon pricing and record it."""
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Razorpay is not configured in Backend/.env.",
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT pl.id, pl.amount, pl.currency
              FROM public.mst_plan pl
              JOIN public.mst_product pr ON pr.id = pl.product_id
             WHERE pl.status = 'active'
               AND pr.status = 'active'
               AND pr.is_active = TRUE
               AND LOWER(pr.name) = LOWER(%s)
             ORDER BY pl.created_date ASC
             LIMIT 1
            """,
            (data.service.strip(),),
        )
        plan = cur.fetchone()

        if not plan:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unknown or inactive service.",
            )

        final_amount = int(plan["amount"])
        currency = str(plan["currency"])
        coupon_id = None

        if data.coupon_code:
            cur.execute(
                """
                SELECT id, code, discount_type, discount_value,
                       max_redemptions, times_redeemed, start_date, expiry_date
                  FROM public.mst_coupon
                 WHERE LOWER(code) = LOWER(%s)
                   AND status = 'active'
                 LIMIT 1
                """,
                (data.coupon_code.strip(),),
            )
            coupon = cur.fetchone()

            if not coupon:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid coupon code.")

            today = date.today()
            start_date = _as_date(coupon["start_date"])
            expiry_date = _as_date(coupon["expiry_date"])

            if start_date and today < start_date:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Coupon is not active yet.")
            if expiry_date and today > expiry_date:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Coupon has expired.")

            max_redemptions = coupon["max_redemptions"]
            if max_redemptions is not None and coupon["times_redeemed"] >= max_redemptions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Coupon redemption limit reached.",
                )

            value = int(coupon["discount_value"])
            if coupon["discount_type"] == "percent":
                final_amount = final_amount - (final_amount * value // 100)
            else:
                final_amount = max(final_amount - value, 0)

            coupon_id = str(coupon["id"])

    order_id = str(uuid.uuid4())

    try:
        razorpay_order = client.order.create(
            {
                "amount": final_amount,
                "currency": currency,
                "receipt": order_id,
                "notes": {
                    "order_id": order_id,
                    "service": data.service,
                },
            }
        )
    except Exception as exc:
        logger.exception("Razorpay order.create failed for order %s", order_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to create the payment order. Please try again.",
        ) from exc

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.orders
              (id, user_id, coupon_id, provider_order_id, payment_provider, amount, currency)
            VALUES (%s, %s, %s, %s, 'razorpay', %s, %s)
            """,
            (
                order_id,
                user_id,
                coupon_id,
                razorpay_order["id"],
                final_amount,
                currency,
            ),
        )
        cur.execute(
            """
            INSERT INTO public.order_items (order_id, plan_id, amount)
            VALUES (%s, %s, %s)
            """,
            (order_id, plan["id"], final_amount),
        )
    conn.commit()

    razorpay_order["key_id"] = settings.razorpay_key_id
    return razorpay_order


@router.post("/verify")
def verify_payment(
    data: PaymentVerification,
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Verify Razorpay signature and capture status, then activate access via PostgreSQL."""
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Razorpay is not configured in Backend/.env.",
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, provider_order_id, amount, payment_status
              FROM public.orders
             WHERE provider_order_id = %s
               AND user_id = %s
             LIMIT 1
            """,
            (data.razorpay_order_id, user_id),
        )
        order = cur.fetchone()

    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found.")

    try:
        client.utility.verify_payment_signature(data.model_dump())
    except Exception:
        return {
            "success": False,
            "message": "Payment verification failed.",
        }

    try:
        payment = client.payment.fetch(data.razorpay_payment_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to check the payment status. Please try again.",
        ) from exc

    if payment.get("order_id") != data.razorpay_order_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payment order mismatch.")

    if int(payment.get("amount", -1)) != int(order["amount"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payment amount mismatch.")

    payment_status = payment.get("status")
    if payment_status == "captured":
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT public.apply_payment_success(
                  %s::text, %s::text, %s::text, %s::integer, %s::boolean
                )
                """,
                (
                    data.razorpay_order_id,
                    data.razorpay_payment_id,
                    payment.get("method"),
                    int(payment["amount"]),
                    True,
                ),
            )
        conn.commit()
        return {
            "success": True,
            "message": "Payment verified successfully!",
        }

    if payment_status == "authorized":
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.orders
                   SET payment_status = 'submitted'
                 WHERE provider_order_id = %s
                   AND user_id = %s
                """,
                (data.razorpay_order_id, user_id),
            )
        conn.commit()
        return {
            "success": False,
            "pending": True,
            "message": "Payment is authorized and awaiting confirmation.",
        }

    return {
        "success": False,
        "message": "Payment has not been captured.",
    }
