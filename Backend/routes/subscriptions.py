# This file needs two endpoints:
# - POST /api/subscriptions/create — authenticate the user, load the selected plan from mst_plan, create the order records, and create a Razorpay subscription using the plan’s provider_plan_id.
# - GET /api/subscriptions/me — return only the logged-in user’s subscriptions.
# Before testing recurring payments, the required Razorpay plan IDs must be saved in mst_plan.provider_plan_id. Your database seed does not automatically create Razorpay plans.


import logging
import os
import uuid
from datetime import datetime, timezone
from uuid import UUID

import razorpay
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from routes.auth import _user_id
from supabase_client import supabase_rest_request

router = APIRouter(
    prefix="/api/subscriptions",
    tags=["Subscriptions"],
)

logger = logging.getLogger(__name__)

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

client = None

if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    client = razorpay.Client(
        auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
    )


class SubscriptionRequest(BaseModel):
    plan_id: str = Field(min_length=1)


def check_response(response, message):
    if response.status_code >= 400:
        logger.error(
            "%s: %s %s",
            message,
            response.status_code,
            response.text,
        )
        raise HTTPException(
            status_code=500,
            detail=message,
        )

    try:
        return response.json()
    except ValueError:
        logger.exception("%s: Invalid JSON response", message)
        raise HTTPException(
            status_code=502,
            detail="Invalid response from the database service.",
        )

async def get_authenticated_user(request: Request) -> str:
    token = request.cookies.get("beevolve_access")

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Please log in first.",
        )

    return await _user_id(token)


@router.post("/create")
async def create_subscription(
    data: SubscriptionRequest,
    request: Request,
):
    user_id = await get_authenticated_user(request)

    if client is None:
        raise HTTPException(
            status_code=503,
            detail="Razorpay is not configured.",
        )

    # Load an active plan configured for Razorpay subscriptions.
    plan_response = await supabase_rest_request(
        "GET",
        "mst_plan",
        params={
            "select": "id,product_id,amount,currency,duration_days,provider_plan_id",
            "id": f"eq.{data.plan_id}",
            "status": "eq.active",
            "provider_plan_id": "not.is.null",
            "limit": "1",
        },
    )

    plans = check_response(
        plan_response,
        "Unable to load the selected plan.",
    )

    if not plans:
        raise HTTPException(
            status_code=400,
            detail="Plan not found or not configured for autopay.",
        )

    plan = plans[0]
    order_id = str(uuid.uuid4())

    # Create the local order before starting the Razorpay subscription.
    order_response = await supabase_rest_request(
        "POST",
        "orders",
        json={
            "id": order_id,
            "user_id": user_id,
            "payment_mode": "e-mandate",
            "payment_provider": "razorpay",
            "amount": int(plan["amount"]),
            "currency": plan["currency"],
        },
        extra_headers={"Prefer": "return=minimal"},
    )

    check_response(order_response, "Unable to create the order.")

    item_response = await supabase_rest_request(
        "POST",
        "order_items",
        json={
            "order_id": order_id,
            "plan_id": plan["id"],
            "amount": int(plan["amount"]),
        },
        extra_headers={"Prefer": "return=minimal"},
    )

    check_response(
        item_response,
        "Unable to save the subscription order item.",
    )

    # Ask Razorpay to create the recurring subscription.
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
    except Exception:
        logger.exception(
            "Razorpay subscription creation failed for order %s",
            order_id,
        )
        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to start the subscription. "
                "The local order may still exist; contact support "
                "before retrying."
            ),
        )

    return {
        "success": True,
        "order_id": order_id,
        "subscription_id": subscription.get("id"),
        "short_url": subscription.get("short_url"),
        "status": subscription.get("status"),
    }


@router.get("/me")
async def get_my_subscriptions(request: Request):
    user_id = await get_authenticated_user(request)

    response = await supabase_rest_request(
        "GET",
        "subscriptions",
        params={
            "select": (
                "id,product_id,plan_id,order_id,"
                "subscription_status,starts_at,expires_at,"
                "auto_renew,provider_subscription_id,"
                "auth_status,next_charge_at,"
                "mst_plan(plan_interval,duration_days,amount,currency)"
            ),
            "user_id": f"eq.{user_id}",
            "order": "created_date.desc",
        },
    )

    subscriptions = check_response(
        response,
        "Unable to load your subscriptions.",
    )

    return {"subscriptions": subscriptions}

    
@router.get("/access/{product_id}")
async def check_product_access(
    product_id: UUID,
    request: Request,
):
    user_id = await get_authenticated_user(request)

    response = await supabase_rest_request(
        "GET",
        "subscriptions",
        params={
            "select": "id,subscription_status,starts_at,expires_at",
            "user_id": f"eq.{user_id}",
            "product_id": f"eq.{product_id}",
            "subscription_status": "eq.active",
            "status": "eq.active",
        },
    )

    records = check_response(
        response,
        "Unable to verify product access.",
    )

    now = datetime.now(timezone.utc)

    for record in records:
        starts_at = record.get("starts_at")
        expires_at = record.get("expires_at")

        if starts_at:
            start = datetime.fromisoformat(
                starts_at.replace("Z", "+00:00")
            )
            if start > now:
                continue

        if expires_at:
            expiry = datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            )
            if expiry <= now:
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
