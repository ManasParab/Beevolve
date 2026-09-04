import os
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from twilio.base.exceptions import TwilioRestException

from supabase_client import (
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    SUPABASE_SECRET_KEY,
    supabase_request,
    supabase_rest_request,
)
from twilio_client import twilio_client, TWILIO_VERIFY_SERVICE_SID

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500/Frontend").rstrip("/")

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

class SendOtpRequest(BaseModel):
    mobile: str

class VerifyOtpRequest(BaseModel):
    mobile: str
    code: str
    user_id: str
    email: EmailStr

class SendEmailVerificationRequest(BaseModel):
    email: EmailStr

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
        "message": "Account created. Choose how you'd like to verify your account.",
        "authenticated": False,
        "user_id": user.get("id"),
    }


@router.post("/send-verification-email")
async def send_verification_email(data: SendEmailVerificationRequest):
    """Sends Supabase's standard 'Confirm your signup' email — only called
    when the user explicitly clicks 'Verify with email'."""
    resp = await supabase_request(
        "POST",
        "resend",
        json={
            "type": "signup",
            "email": str(data.email),
            "options": {"email_redirect_to": f"{FRONTEND_URL}/index.html"},
        },
    )

    if resp.status_code >= 400:
        try:
            body = resp.json()
        except Exception:
            body = {}
        raise HTTPException(
            status_code=400,
            detail=friendly_supabase_error(body, "Unable to send the verification email."),
        )

    return {"success": True, "message": "Verification email sent."}

@router.post("/otp/send")
async def send_otp(data: SendOtpRequest):
    """Sends a one-time code to the given mobile number using Twilio Verify."""
    print("OTP SEND ATTEMPT -> mobile:", repr(data.mobile), "| service sid:", repr(TWILIO_VERIFY_SERVICE_SID))
    try:
        verification = twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
            .verifications.create(to=data.mobile, channel="sms")
    except TwilioRestException as e:
        print("TWILIO ERROR -> status:", e.status, "| code:", e.code, "| msg:", e.msg, "| more_info:", e.uri)
        raise HTTPException(
            status_code=400,
            detail=f"[{e.code}] {e.msg}" if e.msg else "Unable to send the OTP. Please check the mobile number.",
        )

    return {
        "success": True,
        "status": verification.status,
        "message": "We've sent a code to your mobile number.",
    }


@router.post("/otp/verify")
async def verify_otp(data: VerifyOtpRequest, response: Response):
    """Checks the OTP with Twilio, then confirms + logs the user into Supabase."""

    print("OTP VERIFY ATTEMPT -> mobile:", repr(data.mobile), "| code:", repr(data.code), "| user_id:", repr(data.user_id), "| email:", repr(data.email))

    # 1) Ask Twilio if the code the user typed is correct.
    try:
        check = twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
            .verification_checks.create(to=data.mobile, code=data.code)
    except TwilioRestException as e:
        print("STEP 1 (twilio check) FAILED -> status:", e.status, "| code:", e.code, "| msg:", e.msg)
        raise HTTPException(
            status_code=400,
            detail=f"[{e.code}] {e.msg}" if e.msg else "Unable to verify the code. Please try again.",
        )

    print("STEP 1 (twilio check) OK -> status:", check.status)

    if check.status != "approved":
        raise HTTPException(status_code=400, detail="Incorrect or expired code. Please try again.")

    # 2) Code was correct -> mark this Supabase user as verified (email + phone).
    confirm = await supabase_request(
        "PUT",
        f"admin/users/{data.user_id}",
        json={"email_confirm": True, "phone": data.mobile, "phone_confirm": True},
        access_token=SUPABASE_SECRET_KEY,
    )
    print("STEP 2 (confirm user) -> status:", confirm.status_code, "| body:", confirm.text)
    if confirm.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"Step 2 failed [{confirm.status_code}]: {confirm.text}")

    # 3) Generate a one-time login link for this user (server-side only, never shown to them)...
    link = await supabase_request(
        "POST",
        "admin/generate_link",
        json={"type": "magiclink", "email": str(data.email)},
        access_token=SUPABASE_SECRET_KEY,
    )
    print("STEP 3 (generate_link) -> status:", link.status_code, "| body:", link.text)
    if link.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"Step 3 failed [{link.status_code}]: {link.text}")

    link_body = link.json()
    token_hash = (link_body.get("properties") or {}).get("hashed_token") or link_body.get("hashed_token")
    print("STEP 3 token_hash found:", bool(token_hash))
    if not token_hash:
        raise HTTPException(status_code=400, detail="Step 3 failed: no hashed_token in generate_link response.")

    # ...and immediately redeem it for a real session (access + refresh tokens).
    session = await supabase_request(
        "POST",
        "verify",
        json={"type": "magiclink", "token_hash": token_hash},
    )
    print("STEP 4 (redeem token) -> status:", session.status_code, "| body:", session.text)
    if session.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"Step 4 failed [{session.status_code}]: {session.text}")

    session_body = session.json()
    access_token = session_body.get("access_token")
    refresh_token = session_body.get("refresh_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Step 4 failed: no access_token in verify response.")

    # 4) Log them in exactly like /login does.
    set_session_cookies(response, access_token, refresh_token)
    return {
        "success": True,
        "authenticated": True,
        "message": "Mobile number verified successfully.",
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
