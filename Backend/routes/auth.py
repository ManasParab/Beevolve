import os
import re
import secrets
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from supabase_client import (
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    SUPABASE_SECRET_KEY,
    supabase_request,
    supabase_rest_request,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500/Frontend").rstrip("/")

# ============================================================
# EMAIL OTP SETTINGS
# ============================================================

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USERNAME or "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Beevolve")

EMAIL_OTP_EXPIRY_MINUTES = int(
    os.getenv("EMAIL_OTP_EXPIRY_MINUTES", "5")
)

EMAIL_OTP_MAX_ATTEMPTS = int(
    os.getenv("EMAIL_OTP_MAX_ATTEMPTS", "5")
)

EMAIL_OTP_RESEND_SECONDS = int(
    os.getenv("EMAIL_OTP_RESEND_SECONDS", "60")
)

EMAIL_OTP_PEPPER = os.getenv("EMAIL_OTP_PEPPER")

if not SMTP_USERNAME:
    print("WARNING: SMTP_USERNAME is missing from .env")

if not SMTP_PASSWORD:
    print("WARNING: SMTP_PASSWORD is missing from .env")

if not EMAIL_OTP_PEPPER:
    print("WARNING: EMAIL_OTP_PEPPER is missing from .env")

COOKIE_KWARGS = {
    "httponly": True,
    "secure": COOKIE_SECURE,
    "samesite": "lax",
    "path": "/",
}

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class OAuthExchangeRequest(BaseModel):
    access_token: str
    refresh_token: str | None = None

class UpdatePasswordRequest(BaseModel):
    password: str

class UpdateProfileRequest(BaseModel):
    full_name: str
    mobile: str = ""
    email: EmailStr

class SendEmailOtpRequest(BaseModel):
    email: EmailStr
    user_id: str

class VerifyEmailOtpRequest(BaseModel):
    email: EmailStr
    user_id: str
    code: str

def set_session_cookies(response: Response, access_token: str, refresh_token: str | None):
    response.set_cookie("beevolve_access", access_token, max_age=3600, **COOKIE_KWARGS)
    if refresh_token:
        response.set_cookie("beevolve_refresh", refresh_token, max_age=60 * 60 * 24 * 30, **COOKIE_KWARGS)

def clear_session_cookies(response: Response):
    response.delete_cookie("beevolve_access", path="/")
    response.delete_cookie("beevolve_refresh", path="/")

def friendly_supabase_error(payload: dict, fallback: str):
    message = payload.get("msg") or payload.get("message") or payload.get("error_description") or payload.get("error")
    return message or fallback

# ============================================================
# EMAIL OTP HELPERS
# ============================================================

def generate_email_otp() -> str:
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    numbers = "23456789"

    # Guarantee at least 1 letter and 1 number
    otp = [
        secrets.choice(letters),
        secrets.choice(numbers)
    ]

    # Fill remaining 4 characters
    alphabet = letters + numbers
    otp.extend(secrets.choice(alphabet) for _ in range(4))

    # Shuffle so the number isn't always in position 2
    secrets.SystemRandom().shuffle(otp)

    return "".join(otp)


def hash_email_otp(otp: str) -> str:
    """
    Hash the OTP before storing it in the database.
    """
    if not EMAIL_OTP_PEPPER:
        raise RuntimeError("EMAIL_OTP_PEPPER is missing from .env")

    normalized = otp.strip().upper()

    return hashlib.sha256(
        f"{EMAIL_OTP_PEPPER}:{normalized}".encode("utf-8")
    ).hexdigest()


def send_email_otp_message(to_email: str, otp: str):
    """
    Sends the OTP through Gmail SMTP.
    """

    if not SMTP_USERNAME or not SMTP_PASSWORD:
        raise RuntimeError("Gmail SMTP credentials are missing.")

    message = EmailMessage()

    message["Subject"] = "Beevolve email verification code"
    message["From"] = (
        f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        if SMTP_FROM_EMAIL
        else SMTP_USERNAME
    )
    message["To"] = to_email

    message.set_content(
        f"""Hi,

Your Beevolve email verification code is:

{otp}

This code will expire in {EMAIL_OTP_EXPIRY_MINUTES} minutes.

If you did not create a Beevolve account, you can safely ignore this email.

Regards,
Beevolve Team
"""
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)

@router.post("/register")
async def register_user(data: RegisterRequest, response: Response):

    # Create the user via the ADMIN API instead of the public /signup endpoint.
    # This does NOT send any email automatically, and gives us a clean,
    # honest error if the email is genuinely already registered (no more
    # guessing based on an empty "identities" list).
    payload = {
        "email": data.email,
        "password": data.password,
        "email_confirm": False,
        "phone_confirm": False,
        "user_metadata": {
            "full_name": data.name,
            "mobile": data.mobile,
        },
    }

    supa = await supabase_request(
        "POST",
        "admin/users",
        json=payload,
        access_token=SUPABASE_SECRET_KEY,
    )

    try:
        body = supa.json()
        print("SUPABASE CREATE USER RESPONSE:", body)
    except Exception:
        body = {}

    if supa.status_code >= 400:
        message = friendly_supabase_error(body, "Registration failed.")

        if "already" in message.lower() and "registered" in message.lower():
            message = "An account with this email already exists. Please sign in."
        elif "already" in message.lower() and "exists" in message.lower():
            message = "An account with this email already exists. Please sign in."

        raise HTTPException(status_code=400, detail=message)

    user = body or {}
    if not user.get("id"):
        raise HTTPException(status_code=400, detail="Registration failed. Please try again.")

    return {
    "success": True,
    "message": "Account created. Please verify your email.",
    "authenticated": False,
    "user_id": user.get("id"),
}

# ============================================================
# SEND EMAIL OTP
# ============================================================

@router.post("/email-otp/send")
async def send_email_otp(data: SendEmailOtpRequest):

    email = str(data.email).strip().lower()
    user_id = data.user_id.strip()

    # --------------------------------------------------------
    # Check that this user actually exists
    # --------------------------------------------------------

    user_resp = await supabase_request(
        "GET",
        f"admin/users/{user_id}",
        access_token=SUPABASE_SECRET_KEY,
    )

    if user_resp.status_code >= 400:
        raise HTTPException(
            status_code=400,
            detail="Invalid registration session. Please create your account again.",
        )

    try:
        user = user_resp.json()
    except Exception:
        user = {}

    if str(user.get("email", "")).lower() != email:
        raise HTTPException(
            status_code=400,
            detail="Email does not match the registered account.",
        )

    if user.get("email_confirmed_at"):
        raise HTTPException(
            status_code=400,
            detail="This email is already verified.",
        )

    # --------------------------------------------------------
    # Check resend cooldown
    # --------------------------------------------------------

    existing = await supabase_rest_request(
        "GET",
        "email_otps",
        params={
            "select": "created_at",
            "user_id": f"eq.{user_id}",
            "order": "created_at.desc",
            "limit": "1",
        },
        access_token=SUPABASE_SECRET_KEY,
    )

    if existing.status_code < 400:
        try:
            rows = existing.json()
        except Exception:
            rows = []

        if rows:
            created_at = datetime.fromisoformat(
                rows[0]["created_at"].replace("Z", "+00:00")
            )

            elapsed = (
                datetime.now(timezone.utc) - created_at
            ).total_seconds()

            if elapsed < EMAIL_OTP_RESEND_SECONDS:
                remaining = int(
                    EMAIL_OTP_RESEND_SECONDS - elapsed
                )

                raise HTTPException(
                    status_code=429,
                    detail=f"Please wait {remaining} seconds before requesting another code.",
                )

    # --------------------------------------------------------
    # Generate OTP
    # --------------------------------------------------------

    otp = generate_email_otp()
    otp_hash = hash_email_otp(otp)

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=EMAIL_OTP_EXPIRY_MINUTES)
    )

    # --------------------------------------------------------
    # Delete previous OTPs for this user
    # --------------------------------------------------------

    await supabase_rest_request(
        "DELETE",
        "email_otps",
        params={
            "user_id": f"eq.{user_id}",
        },
        access_token=SUPABASE_SECRET_KEY,
    )

    # --------------------------------------------------------
    # Store new OTP
    # --------------------------------------------------------

    stored = await supabase_rest_request(
        "POST",
        "email_otps",
        json={
            "user_id": user_id,
            "email": email,
            "otp_hash": otp_hash,
            "expires_at": expires_at.isoformat(),
            "attempts": 0,
        },
        access_token=SUPABASE_SECRET_KEY,
    )

    if stored.status_code >= 400:
        print(
            "EMAIL OTP DB ERROR:",
            stored.status_code,
            stored.text,
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to create the verification code.",
        )

    # --------------------------------------------------------
    # Send email
    # --------------------------------------------------------

    try:
        send_email_otp_message(email, otp)

    except Exception as exc:
        print("EMAIL OTP SEND ERROR:", repr(exc))

        # Do not leave a valid OTP behind if email sending failed.
        await supabase_rest_request(
            "DELETE",
            "email_otps",
            params={
                "user_id": f"eq.{user_id}",
            },
            access_token=SUPABASE_SECRET_KEY,
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to send the verification email. Please try again.",
        )

    return {
        "success": True,
        "message": "A 6-character verification code has been sent to your email.",
    }

# ============================================================
# VERIFY EMAIL OTP
# ============================================================

@router.post("/email-otp/verify")
async def verify_email_otp(
    data: VerifyEmailOtpRequest,
    response: Response,
):

    email = str(data.email).strip().lower()
    user_id = data.user_id.strip()
    code = data.code.strip().upper()

    # --------------------------------------------------------
    # Basic OTP validation
    # --------------------------------------------------------

    if not re.fullmatch(r"[A-Z0-9]{6}", code):
        raise HTTPException(
            status_code=400,
            detail="Please enter the 6-character verification code.",
        )

    # --------------------------------------------------------
    # Get latest OTP
    # --------------------------------------------------------

    otp_resp = await supabase_rest_request(
        "GET",
        "email_otps",
        params={
            "select": "id,email,otp_hash,expires_at,attempts",
            "user_id": f"eq.{user_id}",
            "email": f"eq.{email}",
            "order": "created_at.desc",
            "limit": "1",
        },
        access_token=SUPABASE_SECRET_KEY,
    )

    if otp_resp.status_code >= 400:
        raise HTTPException(
            status_code=500,
            detail="Unable to verify the code right now.",
        )

    try:
        rows = otp_resp.json()
    except Exception:
        rows = []

    if not rows:
        raise HTTPException(
            status_code=400,
            detail="No active verification code found. Please request a new code.",
        )

    otp_record = rows[0]

    # --------------------------------------------------------
    # Check expiry
    # --------------------------------------------------------

    expires_at = datetime.fromisoformat(
        otp_record["expires_at"].replace("Z", "+00:00")
    )

    if datetime.now(timezone.utc) > expires_at:

        await supabase_rest_request(
            "DELETE",
            "email_otps",
            params={
                "id": f"eq.{otp_record['id']}",
            },
            access_token=SUPABASE_SECRET_KEY,
        )

        raise HTTPException(
            status_code=400,
            detail="This verification code has expired. Please request a new one.",
        )

    # --------------------------------------------------------
    # Check attempts
    # --------------------------------------------------------

    attempts = int(otp_record.get("attempts", 0))

    if attempts >= EMAIL_OTP_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=400,
            detail="Too many incorrect attempts. Please request a new code.",
        )

    # --------------------------------------------------------
    # Compare hashed OTP
    # --------------------------------------------------------

    supplied_hash = hash_email_otp(code)

    if not hmac.compare_digest(
        supplied_hash,
        otp_record["otp_hash"],
    ):

        await supabase_rest_request(
            "PATCH",
            "email_otps",
            json={
                "attempts": attempts + 1,
            },
            params={
                "id": f"eq.{otp_record['id']}",
            },
            access_token=SUPABASE_SECRET_KEY,
        )

        remaining = EMAIL_OTP_MAX_ATTEMPTS - attempts - 1

        if remaining <= 0:
            message = "Too many incorrect attempts. Please request a new code."
        else:
            message = f"Incorrect verification code. {remaining} attempts remaining."

        raise HTTPException(
            status_code=400,
            detail=message,
        )

    # --------------------------------------------------------
    # OTP correct → confirm email
    # --------------------------------------------------------

    confirm_resp = await supabase_request(
        "PUT",
        f"admin/users/{user_id}",
        json={
            "email_confirm": True,
        },
        access_token=SUPABASE_SECRET_KEY,
    )

    if confirm_resp.status_code >= 400:
        print(
            "EMAIL CONFIRM ERROR:",
            confirm_resp.status_code,
            confirm_resp.text,
        )

        raise HTTPException(
            status_code=500,
            detail="OTP was correct, but the email could not be verified.",
        )

    # --------------------------------------------------------
    # Delete used OTP
    # --------------------------------------------------------

    await supabase_rest_request(
        "DELETE",
        "email_otps",
        params={
            "id": f"eq.{otp_record['id']}",
        },
        access_token=SUPABASE_SECRET_KEY,
    )

    # We intentionally do NOT try to login here using a password.
    # The frontend will send the user to the normal login screen.
    # --------------------------------------------------------

    return {
        "success": True,
        "authenticated": False,
        "message": "Email verified successfully. You can now sign in.",
    }

@router.post("/login")
async def login_user(data: LoginRequest, response: Response):
    supa = await supabase_request(
        "POST",
        "token?grant_type=password",
        json={"email": data.email, "password": data.password},
    )

    try:
        body = supa.json()
    except Exception:
        body = {}

    if supa.status_code >= 400:
        message = friendly_supabase_error(body, "Invalid email or password.")
        lower = message.lower()
        if "email not confirmed" in lower:
            message = "Please verify your email before signing in."
        elif "invalid login credentials" in lower:
            message = "Incorrect email or password."
        raise HTTPException(status_code=401, detail=message)

    access_token = body.get("access_token")
    refresh_token = body.get("refresh_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Login failed.")

    set_session_cookies(response, access_token, refresh_token)

    return {
        "success": True,
        "message": "Login successful.",
        "authenticated": True,
    }

@router.get("/me")
async def current_user(request: Request):
    access_token = request.cookies.get("beevolve_access")
    if not access_token:
        return {"authenticated": False}

    supa = await supabase_request("GET", "user", access_token=access_token)
    if supa.status_code >= 400:
        return {"authenticated": False}

    body = supa.json()
    return {
        "authenticated": True,
        "user": {
            "id": body.get("id"),
            "email": body.get("email"),
            "user_metadata": body.get("user_metadata") or {},
        },
    }

@router.post("/refresh")
async def refresh_session(request: Request, response: Response):
    refresh_token = request.cookies.get("beevolve_refresh")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh session.")

    supa = await supabase_request(
        "POST",
        "token?grant_type=refresh_token",
        json={"refresh_token": refresh_token},
    )
    try:
        body = supa.json()
    except Exception:
        body = {}

    if supa.status_code >= 400:
        clear_session_cookies(response)
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")

    set_session_cookies(response, body["access_token"], body.get("refresh_token"))
    return {"success": True, "authenticated": True}

@router.post("/logout")
async def logout(request: Request, response: Response):
    access_token = request.cookies.get("beevolve_access")
    if access_token:
        await supabase_request("POST", "logout", access_token=access_token)
    clear_session_cookies(response)
    return {"success": True}

@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    redirect_to = f"{FRONTEND_URL}/reset-password.html"
    supa = await supabase_request(
        "POST",
        "recover",
        json={"email": data.email, "redirect_to": redirect_to},
    )
    if supa.status_code >= 400:
        try:
            body = supa.json()
        except Exception:
            body = {}
        raise HTTPException(
            status_code=400,
            detail=friendly_supabase_error(body, "Unable to send password reset email."),
        )
    return {"success": True, "message": "If the account exists, a password reset email has been sent."}

@router.get("/oauth/google")
async def google_oauth():
    params = urlencode({
        "provider": "google",
        "redirect_to": f"{FRONTEND_URL}/oauth-callback.html",
    })
    # The authorize endpoint accepts the project API key as a header, not in the
    # browser. The frontend receives only the resulting URL.
    return {
        "url": f"{SUPABASE_URL.rstrip('/')}/auth/v1/authorize?{params}",
    }

@router.get("/oauth/microsoft")
async def microsoft_oauth():
    params = urlencode({
        "provider": "azure",
        "redirect_to": f"{FRONTEND_URL}/oauth-callback.html",
    })
    return {
        "url": f"{SUPABASE_URL.rstrip('/')}/auth/v1/authorize?{params}",
    }

@router.post("/oauth/exchange")
async def oauth_exchange(data: OAuthExchangeRequest, response: Response):
    # OAuth providers return tokens in the URL fragment for the implicit flow.
    # The frontend sends them once to this backend endpoint; the backend immediately
    # converts them into HttpOnly cookies and the token values are never persisted.
    supa = await supabase_request("GET", "user", access_token=data.access_token)
    if supa.status_code >= 400:
        raise HTTPException(status_code=401, detail="OAuth authentication failed.")

    set_session_cookies(response, data.access_token, data.refresh_token)
    return {"success": True, "authenticated": True}


@router.post("/update-password")
async def update_password(data: UpdatePasswordRequest, request: Request, response: Response):
    access_token = request.cookies.get("beevolve_access")
    if not access_token:
        raise HTTPException(status_code=401, detail="Password reset session expired. Please request a new reset email.")

    supa = await supabase_request(
        "PUT",
        "user",
        json={"password": data.password},
        access_token=access_token,
    )
    if supa.status_code >= 400:
        try:
            body = supa.json()
        except Exception:
            body = {}
        raise HTTPException(
            status_code=400,
            detail=friendly_supabase_error(body, "Unable to update password."),
        )

    return {"success": True, "message": "Password updated successfully."}

@router.get("/profile")
async def profile(request: Request):
    access_token = request.cookies.get("beevolve_access")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    supa = await supabase_rest_request(
        "GET",
        "profiles",
        access_token=access_token,
        params={
            "select": "id,full_name,mobile,created_at,updated_at",
            "id": "eq." + (await _user_id(access_token)),
            "limit": "1",
        },
    )

    if supa.status_code >= 400:
        raise HTTPException(status_code=supa.status_code, detail="Unable to load profile.")

    rows = supa.json()
    return {"profile": rows[0] if rows else None}

@router.put("/profile")
async def update_profile(data: UpdateProfileRequest, request: Request):
    access_token = request.cookies.get("beevolve_access")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    user_id = await _user_id(access_token)
    auth_update = await supabase_request(
        "PUT",
        "user",
        json={
            "email": str(data.email),
            "data": {"full_name": data.full_name, "mobile": data.mobile},
        },
        access_token=access_token,
    )
    if auth_update.status_code >= 400:
        try:
            body = auth_update.json()
        except Exception:
            body = {}
        raise HTTPException(status_code=400, detail=friendly_supabase_error(body, "Unable to update account details."))

    profile_update = await supabase_rest_request(
        "PATCH",
        "profiles",
        json={"full_name": data.full_name, "mobile": data.mobile},
        access_token=access_token,
        params={"id": "eq." + user_id},
    )
    if profile_update.status_code >= 400:
        raise HTTPException(status_code=profile_update.status_code, detail="Unable to update profile.")

    return {"success": True, "message": "Profile updated successfully. Check your email if confirmation is required."}

async def _user_id(access_token: str) -> str:
    supa = await supabase_request("GET", "user", access_token=access_token)
    if supa.status_code >= 400:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return supa.json()["id"]
