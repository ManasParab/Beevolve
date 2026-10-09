
import os
import uuid
from datetime import date

import razorpay
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from routes.auth import _user_id
from supabase_client import supabase_rest_request, supabase_rpc

router = APIRouter(prefix="/api/payments", tags=["Payments"])

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    raise RuntimeError(
        "RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are missing from .env"
    )

client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)


class PaymentVerification(BaseModel):
    razorpay_order_id: str = Field(min_length=1)
    razorpay_payment_id: str = Field(min_length=1)
    razorpay_signature: str = Field(min_length=1)


class OrderRequest(BaseModel):
    service: str = "Career Toolkit"
    coupon_code: str | None = None


def require_success(response, message: str):
    if response.status_code >= 400:
        print("DATABASE ERROR:", response.status_code, response.text)
        raise HTTPException(status_code=500, detail=message)

    try:
        return response.json()
    except Exception:
        return []


async def get_authenticated_user(request: Request) -> tuple[str, str]:
    token = request.cookies.get("beevolve_access")

    if not token:
        raise HTTPException(status_code=401, detail="Please log in first.")

    user_id = await _user_id(token)
    return token, user_id


@router.post("/create-order")
async def create_order(data: OrderRequest, request: Request):
    _, user_id = await get_authenticated_user(request)

    # Find the active plan for this service.
    plan_response = await supabase_rest_request(
        "GET",
        "mst_plan",
        params={
            "select": "id,product_id,amount,currency,duration_days,mst_product!inner(name,is_active,status)",
            "status": "eq.active",
            "mst_product.name": f"eq.{data.service}",
            "mst_product.is_active": "eq.true",
            "mst_product.status": "eq.active",
            "limit": "1",
        },
    )
    plans = require_success(plan_response, "Unable to load the selected plan.")

    if not plans:
        raise HTTPException(status_code=400, detail="Unknown or inactive service.")

    plan = plans[0]
    final_amount = int(plan["amount"])
    currency = plan["currency"]
    coupon_id = None

    # Validate a coupon if one was supplied.
    if data.coupon_code:
        coupon_response = await supabase_rest_request(
            "GET",
            "mst_coupon",
            params={
                "select": "id,code,discount_type,discount_value,max_redemptions,times_redeemed,start_date,expiry_date",
                "code": f"eq.{data.coupon_code.strip()}",
                "status": "eq.active",
                "limit": "1",
            },
        )
        coupons = require_success(
            coupon_response, "Unable to validate the coupon."
        )

        if not coupons:
            raise HTTPException(status_code=400, detail="Invalid coupon code.")

        coupon = coupons[0]
        today = date.today()

        if coupon["start_date"] and today < date.fromisoformat(coupon["start_date"]):
            raise HTTPException(status_code=400, detail="Coupon is not active yet.")

        if coupon["expiry_date"] and today > date.fromisoformat(coupon["expiry_date"]):
            raise HTTPException(status_code=400, detail="Coupon has expired.")

        max_redemptions = coupon["max_redemptions"]
        if (
            max_redemptions is not None
            and coupon["times_redeemed"] >= max_redemptions
        ):
            raise HTTPException(status_code=400, detail="Coupon redemption limit reached.")

        value = int(coupon["discount_value"])

        if coupon["discount_type"] == "percent":
            final_amount = final_amount - (final_amount * value // 100)
        else:
            final_amount = max(final_amount - value, 0)

        coupon_id = coupon["id"]

    order_id = str(uuid.uuid4())

    # Create the Razorpay order using the server-calculated amount.
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
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Unable to create the payment order. Please try again.",
        )

    # Save the order in the database.
    order_response = await supabase_rest_request(
        "POST",
        "orders",
        json={
            "id": order_id,
            "user_id": user_id,
            "coupon_id": coupon_id,
            "provider_order_id": razorpay_order["id"],
            "payment_provider": "razorpay",
            "amount": final_amount,
            "currency": currency,
        },
        extra_headers={"Prefer": "return=minimal"},
    )

    if order_response.status_code >= 400:
        print("ORDER SAVE ERROR:", order_response.status_code, order_response.text)
        raise HTTPException(
            status_code=500,
            detail="Unable to save the order. Please contact support before retrying.",
        )

    # Save the selected plan against the order.
    item_response = await supabase_rest_request(
        "POST",
        "order_items",
        json={
            "order_id": order_id,
            "plan_id": plan["id"],
            "amount": final_amount,
        },
        extra_headers={"Prefer": "return=minimal"},
    )

    if item_response.status_code >= 400:
        print("ORDER ITEM SAVE ERROR:", item_response.status_code, item_response.text)
        raise HTTPException(
            status_code=500,
            detail="The order was created but its item could not be saved. Please contact support.",
        )

    razorpay_order["key_id"] = RAZORPAY_KEY_ID
    return razorpay_order


@router.post("/verify")
async def verify_payment(data: PaymentVerification, request: Request):
    _, user_id = await get_authenticated_user(request)

    # Make sure this order belongs to the logged-in user.
    order_response = await supabase_rest_request(
        "GET",
        "orders",
        params={
            "select": "id,provider_order_id,amount,payment_status",
            "provider_order_id": f"eq.{data.razorpay_order_id}",
            "user_id": f"eq.{user_id}",
            "limit": "1",
        },
    )
    orders = require_success(order_response, "Unable to check this order.")

    if not orders:
        raise HTTPException(status_code=404, detail="Order not found.")

    order = orders[0]

    # Reject an invalid signature without changing the database.
    try:
        client.utility.verify_payment_signature(data.model_dump())
    except Exception:
        return {
            "success": False,
            "message": "Payment verification failed.",
        }

    try:
        payment = client.payment.fetch(data.razorpay_payment_id)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Unable to check the payment status. Please try again.",
        )

    if payment.get("order_id") != data.razorpay_order_id:
        raise HTTPException(status_code=400, detail="Payment order mismatch.")

    if int(payment.get("amount", -1)) != int(order["amount"]):
        raise HTTPException(status_code=400, detail="Payment amount mismatch.")

    if payment.get("status") == "captured":
        rpc_response = await supabase_rpc(
            "apply_payment_success",
            {
                "p_provider_order_id": data.razorpay_order_id,
                "p_provider_payment_id": data.razorpay_payment_id,
                "p_payment_mode": payment.get("method"),
                "p_amount": int(payment["amount"]),
                "p_signature_verified": True,
            },
        )

        if rpc_response.status_code >= 400:
            print("PAYMENT RPC ERROR:", rpc_response.status_code, rpc_response.text)
            raise HTTPException(
                status_code=500,
                detail="Payment was received but could not be recorded. Please contact support.",
            )

        return {
            "success": True,
            "message": "Payment verified successfully!",
        }

    if payment.get("status") == "authorized":
        pending_response = await supabase_rest_request(
            "PATCH",
            "orders",
            params={
                "provider_order_id": f"eq.{data.razorpay_order_id}",
                "user_id": f"eq.{user_id}",
            },
            json={"payment_status": "submitted"},
            extra_headers={"Prefer": "return=minimal"},
        )

        if pending_response.status_code >= 400:
            print("PAYMENT STATUS ERROR:", pending_response.status_code, pending_response.text)
            raise HTTPException(
                status_code=500,
                detail="Unable to update payment status.",
            )

        return {
            "success": False,
            "pending": True,
            "message": "Payment is authorized and awaiting confirmation.",
        }

    return {
        "success": False,
        "message": "Payment has not been captured.",
    }
