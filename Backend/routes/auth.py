import os
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from supabase_client import (
    SUPABASE_URL,
    SUPABASE_ANON_KEY,
    supabase_request,
    supabase_rest_request,
)

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
    payload = {
    "email": data.email,
    "password": data.password,
    "data": {
        "full_name": data.name,
        "mobile": data.mobile,
    },
    "options": {
        "email_redirect_to": f"{FRONTEND_URL}/index.html"
    },
}

    supa = await supabase_request("POST", "signup", json=payload)

    try:
        body = supa.json()
    except Exception:
        body = {}

    if supa.status_code >= 400:
        message = friendly_supabase_error(body, "Registration failed.")
        if "already registered" in message.lower():
            message = "An account with this email already exists. Please sign in."
        raise HTTPException(status_code=400, detail=message)

    user = body.get("user") or {}
    identities = user.get("identities")

    # Supabase can return an existing confirmed user with an empty identities list
    # when email enumeration protection is enabled.
    if identities == []:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please sign in.",
        )

    session = body.get("session") or {}
    if session.get("access_token"):
        set_session_cookies(response, session["access_token"], session.get("refresh_token"))

    return {
        "success": True,
        "message": (
            "Account created. Please check your email for verification."
            if not session.get("access_token")
            else "Account created successfully."
        ),
        "authenticated": bool(session.get("access_token")),
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

async def _user_id(access_token: str) -> str:
    supa = await supabase_request("GET", "user", access_token=access_token)
    if supa.status_code >= 400:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return supa.json()["id"]
