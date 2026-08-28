import os

import razorpay
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/payments", tags=["Payments"])

SERVICE_PRICES = {
    "Career Toolkit": 499,
    "Portfolio Review": 299,
    "Career Roadmap": 199,
}

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    raise RuntimeError("RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are missing from .env")

client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


class PaymentVerification(BaseModel):
    razorpay_order_id: str = Field(min_length=1)
    razorpay_payment_id: str = Field(min_length=1)
    razorpay_signature: str = Field(min_length=1)


class OrderRequest(BaseModel):
    service: str = "Career Toolkit"


@router.post("/create-order")
def create_order(data: OrderRequest):
    price = SERVICE_PRICES.get(data.service)
    if price is None:
        raise HTTPException(status_code=400, detail="Unknown Beevolve service.")

    order = client.order.create({
        "amount": price * 100,
        "currency": "INR",
        "receipt": "beevolve_purchase",
        "notes": {"service": data.service},
    })
    order["key_id"] = RAZORPAY_KEY_ID
    return order


@router.post("/verify")
def verify_payment(data: PaymentVerification):
    try:
        client.utility.verify_payment_signature(data.model_dump())
    except Exception:
        return {"success": False, "message": "Payment verification failed."}

    return {"success": True, "message": "Payment verified successfully!"}
