"""Authentication, OTP verification, session cookie, profile, and Google OAuth routes."""

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import hmac
import logging
import smtplib
import time
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
import httpx
import _pg_bootstrap  # noqa: F401
import psycopg
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, EmailStr, Field

from config import settings
from database import get_db
from security import (
    TokenError,
    create_access_token,
    create_oauth_state,
    create_reset_token,
    decode_access_token,
    decode_reset_token,
    generate_email_otp,
    generate_refresh_token,
    hash_email_otp,
    hash_password,
    hash_refresh_token,
    normalize_indian_mobile,
    validate_password_strength,
    verify_oauth_state,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

# In-memory brute-force lockout protection keyed by client IP + lowercase email.
_login_attempts: dict[str, dict[str, float | int]] = {}


def _cookie_kwargs() -> dict[str, Any]:
    return {
        "httponly": True,
        "secure": settings.cookie_secure,
        "samesite": settings.cookie_samesite,
        "path": "/",
    }


def set_session_cookies(
    response: Response,
    access_token: str,
    refresh_token: str | None,
) -> None:
    """Attach HttpOnly access and refresh session cookies to a response."""
    kwargs = _cookie_kwargs()
    response.set_cookie(
        settings.access_cookie_name,
        access_token,
        max_age=settings.access_token_expire_minutes * 60,
        **kwargs,
    )
    if refresh_token:
        response.set_cookie(
            settings.refresh_cookie_name,
            refresh_token,
            max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
            **kwargs,
        )


def clear_session_cookies(response: Response) -> None:
    """Expire authentication cookies cleanly."""
    for name in (
        settings.access_cookie_name,
        settings.refresh_cookie_name,
        settings.reset_cookie_name,
    ):
        response.delete_cookie(name, path="/")


def extract_access_token(request: Request) -> str | None:
    """Read JWT access token from HttpOnly cookie first, then Authorization header."""
    cookie_token = request.cookies.get(settings.access_cookie_name)
    if cookie_token:
        return cookie_token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip() or None
    return None


def _get_login_key(request: Request, email: str) -> str:
    client_ip = request.client.host if request.client else "unknown"
    return f"{client_ip}:{email.strip().lower()}"


def _serialize_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "full_name": row.get("full_name") or "",
        "mobile": row.get("mobile"),
        "role": row.get("role", "user"),
        "email_verified": bool(row.get("email_verified")),
        "account_status": row.get("account_status", "active"),
    }


def _fetch_active_user_by_id(conn: psycopg.Connection, user_id: str) -> dict[str, Any] | None:
    try:
        parsed_id = str(UUID(str(user_id)))
    except ValueError:
        return None
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, full_name, mobile, role, account_status,
                   email_verified, mfa_enabled, status, created_date, updated_date
              FROM public.users
             WHERE id = %s
               AND deleted_at IS NULL
               AND account_status = 'active'
               AND status = 'active'
             LIMIT 1
            """,
            (parsed_id,),
        )
        return cur.fetchone()


def get_current_user(
    request: Request,
    conn: psycopg.Connection = Depends(get_db),
) -> dict[str, Any]:
    """Authenticate request via HttpOnly cookie or Bearer JWT against PostgreSQL."""
    token = extract_access_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please log in first.",
        )

    try:
        payload = decode_access_token(token)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    user = _fetch_active_user_by_id(conn, str(payload["sub"]))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is unavailable or inactive.",
        )
    return user


def get_current_user_id(user: dict[str, Any] = Depends(get_current_user)) -> str:
    """FastAPI dependency returning the authenticated PostgreSQL user UUID string."""
    return str(user["id"])


def _log_activity(
    conn: psycopg.Connection,
    actor_user_id: str | None,
    action: str,
    entity_type: str = "users",
    entity_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    import json

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.user_activity_log
              (actor_user_id, action, entity_type, entity_id, metadata)
            VALUES (%s, %s, %s, %s, %s::jsonb)
            """,
            (
                actor_user_id,
                action,
                entity_type,
                entity_id,
                json.dumps(metadata or {}),
            ),
        )


def _issue_session_tokens(
    conn: psycopg.Connection,
    user: dict[str, Any],
) -> tuple[str, str, int]:
    """Create JWT access token and persist a hashed refresh token in PostgreSQL."""
    user_id = str(user["id"])
    access_token, expires_in = create_access_token(
        user_id=user_id,
        email=str(user["email"]),
        role=str(user.get("role", "user")),
    )
    raw_refresh = generate_refresh_token()
    refresh_hash = hash_refresh_token(raw_refresh)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.refresh_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user_id, refresh_hash, expires_at),
        )

    return access_token, raw_refresh, expires_in


def _send_smtp_email(to_email: str, subject: str, body_text: str) -> None:
    if not settings.smtp_username or not settings.smtp_password:
        raise RuntimeError("Gmail SMTP credentials are missing.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = (
        f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
        if settings.smtp_from_email
        else settings.smtp_username
    )
    message["To"] = to_email
    message.set_content(body_text)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(message)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    mobile: str
    password: str
    confirm_password: str | None = None
    terms_accepted: bool = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class OAuthExchangeRequest(BaseModel):
    access_token: str
    refresh_token: str | None = None


class UpdatePasswordRequest(BaseModel):
    password: str
    token: str | None = None


class UpdateProfileRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    mobile: str = ""
    email: EmailStr


class SendEmailOtpRequest(BaseModel):
    email: EmailStr
    user_id: str


class VerifyEmailOtpRequest(BaseModel):
    email: EmailStr
    user_id: str
    code: str


class GoogleIdTokenRequest(BaseModel):
    id_token: str = Field(min_length=10)


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(
    data: RegisterRequest,
    conn: psycopg.Connection = Depends(get_db),
):
    """Validate inputs, check uniqueness in PostgreSQL, bcrypt-hash password, and save user."""
    if not data.terms_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please accept the Terms & Conditions and Privacy Policy.",
        )

    if data.confirm_password is not None and data.password != data.confirm_password:
        raise HTTPException(
            status_code=422,
            detail="Password and confirm_password do not match.",
        )

    pw_error = validate_password_strength(data.password)
    if pw_error:
        raise HTTPException(
            status_code=422,
            detail=pw_error,
        )

    try:
        mobile = normalize_indian_mobile(data.mobile, required=True)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    normalized_email = str(data.email).strip().lower()
    full_name = data.name.strip()

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT email, mobile
              FROM public.users
             WHERE LOWER(email) = LOWER(%s)
                OR mobile = %s
             LIMIT 1
            """,
            (normalized_email, mobile),
        )
        existing = cur.fetchone()
        if existing:
            if str(existing["email"]).lower() == normalized_email:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this email already exists. Please sign in.",
                )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this mobile number already exists.",
            )

        password_hash = hash_password(data.password)
        try:
            cur.execute(
                """
                INSERT INTO public.users
                  (email, full_name, mobile, password_hash, role, email_verified)
                VALUES (%s, %s, %s, %s, 'user', FALSE)
                RETURNING id, email, full_name, mobile, role, email_verified, account_status
                """,
                (normalized_email, full_name, mobile, password_hash),
            )
            created = cur.fetchone()
        except UniqueViolation as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email or mobile already exists.",
            ) from exc

    user_id = str(created["id"])
    _log_activity(conn, user_id, "user_registered", entity_id=user_id)
    conn.commit()

    return {
        "success": True,
        "message": "Account created. Please verify your email.",
        "authenticated": False,
        "user_id": user_id,
        "user": _serialize_user(created),
    }


@router.post("/email-otp/send")
def send_email_otp(
    data: SendEmailOtpRequest,
    conn: psycopg.Connection = Depends(get_db),
):
    """Generate a 6-character OTP, store its salted hash in otp_verifications, and email it."""
    email = str(data.email).strip().lower()
    user = _fetch_active_user_by_id(conn, data.user_id.strip())

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid registration session. Please create your account again.",
        )

    if str(user["email"]).lower() != email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email does not match the registered account.",
        )

    if user.get("email_verified"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email is already verified.",
        )

    user_id = str(user["id"])
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT created_date
              FROM public.otp_verifications
             WHERE user_id = %s
               AND purpose = 'email_verification'
             ORDER BY created_date DESC
             LIMIT 1
            """,
            (user_id,),
        )
        latest = cur.fetchone()
        if latest and latest.get("created_date"):
            elapsed = (datetime.now(timezone.utc) - latest["created_date"]).total_seconds()
            if elapsed < settings.email_otp_resend_seconds:
                remaining = int(settings.email_otp_resend_seconds - elapsed)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Please wait {remaining} seconds before requesting another code.",
                )

        otp = generate_email_otp()
        otp_hash = hash_email_otp(otp)
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.email_otp_expiry_minutes
        )

        cur.execute(
            """
            DELETE FROM public.otp_verifications
             WHERE user_id = %s AND purpose = 'email_verification'
            """,
            (user_id,),
        )
        cur.execute(
            """
            INSERT INTO public.otp_verifications
              (user_id, otp_hash, purpose, expires_at, attempts)
            VALUES (%s, %s, 'email_verification', %s, 0)
            """,
            (user_id, otp_hash, expires_at),
        )
    conn.commit()

    body_text = (
        "Hi,\n\n"
        "Your Beevolve email verification code is:\n\n"
        f"{otp}\n\n"
        f"This code will expire in {settings.email_otp_expiry_minutes} minutes.\n\n"
        "If you did not create a Beevolve account, you can safely ignore this email.\n\n"
        "Regards,\nBeevolve Team\n"
    )
    try:
        _send_smtp_email(email, "Beevolve email verification code", body_text)
    except Exception as exc:
        logger.exception("Email OTP SMTP failure for user %s", user_id)
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM public.otp_verifications
                 WHERE user_id = %s AND purpose = 'email_verification'
                """,
                (user_id,),
            )
        conn.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to send the verification email. Please try again.",
        ) from exc

    return {
        "success": True,
        "message": "A 6-character verification code has been sent to your email.",
    }


@router.post("/email-otp/verify")
def verify_email_otp(
    data: VerifyEmailOtpRequest,
    response: Response,
    conn: psycopg.Connection = Depends(get_db),
):
    """Verify the 6-character email OTP against otp_verifications and mark user verified."""
    import re

    email = str(data.email).strip().lower()
    user = _fetch_active_user_by_id(conn, data.user_id.strip())
    code = data.code.strip().upper()

    if not re.fullmatch(r"[A-Z0-9]{6}", code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please enter the 6-character verification code.",
        )

    if not user or str(user["email"]).lower() != email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification request.",
        )

    user_id = str(user["id"])
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, otp_hash, expires_at, attempts
              FROM public.otp_verifications
             WHERE user_id = %s
               AND purpose = 'email_verification'
             ORDER BY created_date DESC
             LIMIT 1
            """,
            (user_id,),
        )
        otp_record = cur.fetchone()

    if not otp_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active verification code found. Please request a new code.",
        )

    if datetime.now(timezone.utc) > otp_record["expires_at"]:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM public.otp_verifications WHERE id = %s", (otp_record["id"],))
        conn.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This verification code has expired. Please request a new one.",
        )

    attempts = int(otp_record["attempts"])
    if attempts >= settings.email_otp_max_attempts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many incorrect attempts. Please request a new code.",
        )

    supplied_hash = hash_email_otp(code)
    if not hmac.compare_digest(supplied_hash, otp_record["otp_hash"]):
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.otp_verifications SET attempts = attempts + 1 WHERE id = %s",
                (otp_record["id"],),
            )
        conn.commit()
        remaining = settings.email_otp_max_attempts - attempts - 1
        detail = (
            "Too many incorrect attempts. Please request a new code."
            if remaining <= 0
            else f"Incorrect verification code. {remaining} attempts remaining."
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.users SET email_verified = TRUE WHERE id = %s",
            (user_id,),
        )
        cur.execute(
            "DELETE FROM public.otp_verifications WHERE id = %s",
            (otp_record["id"],),
        )
    user["email_verified"] = True
    access_token, raw_refresh, expires_in = _issue_session_tokens(conn, user)
    _log_activity(conn, user_id, "email_verified", entity_id=user_id)
    _log_activity(
        conn,
        user_id,
        "user_logged_in",
        entity_id=user_id,
        metadata={"via": "email_otp"},
    )
    conn.commit()

    set_session_cookies(response, access_token, raw_refresh)
    return {
        "success": True,
        "authenticated": True,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": _serialize_user(user),
        "message": "Email verified! Signing you in…",
    }


@router.post("/login")
def login_user(
    data: LoginRequest,
    request: Request,
    response: Response,
    conn: psycopg.Connection = Depends(get_db),
):
    """Verify email/password via bcrypt in PostgreSQL and issue HttpOnly JWT cookies."""
    key = _get_login_key(request, str(data.email))
    now = time.time()
    record = _login_attempts.get(key, {"count": 0, "locked_until": 0})

    if now < float(record["locked_until"]):
        remaining = int(float(record["locked_until"]) - now)
        minutes = max(1, (remaining + 59) // 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {minutes} minute(s).",
        )

    if record["locked_until"] and now >= float(record["locked_until"]):
        record = {"count": 0, "locked_until": 0}

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, full_name, mobile, password_hash, role,
                   account_status, email_verified, status
              FROM public.users
             WHERE LOWER(email) = LOWER(%s)
               AND deleted_at IS NULL
             LIMIT 1
            """,
            (str(data.email).strip().lower(),),
        )
        user = cur.fetchone()

    def _record_failure(detail: str) -> None:
        record["count"] = int(record["count"]) + 1
        if int(record["count"]) >= settings.login_max_attempts:
            record["locked_until"] = time.time() + settings.login_lockout_seconds
        _login_attempts[key] = record
        if int(record["count"]) >= settings.login_max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Try again in 10 minutes.",
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    if not user:
        _record_failure("Incorrect email or password.")

    if user["account_status"] != "active" or user["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is suspended or inactive.",
        )

    if not user.get("password_hash"):
        _record_failure("This account uses Google Sign-In. Please continue with Google.")

    if not verify_password(data.password, user["password_hash"]):
        _record_failure("Incorrect email or password.")

    if settings.require_email_verification and not user.get("email_verified"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please verify your email before signing in.",
        )

    _login_attempts.pop(key, None)
    access_token, raw_refresh, expires_in = _issue_session_tokens(conn, user)
    _log_activity(conn, str(user["id"]), "user_logged_in", entity_id=str(user["id"]))
    conn.commit()

    set_session_cookies(response, access_token, raw_refresh)
    return {
        "success": True,
        "message": "Login successful.",
        "authenticated": True,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": _serialize_user(user),
    }


@router.get("/me")
def current_user(
    request: Request,
    conn: psycopg.Connection = Depends(get_db),
):
    """Return current session state expected by the frontend without throwing on guests."""
    token = extract_access_token(request)
    if not token:
        return {"authenticated": False}

    try:
        payload = decode_access_token(token)
    except TokenError:
        return {"authenticated": False}

    user = _fetch_active_user_by_id(conn, str(payload["sub"]))
    if not user:
        return {"authenticated": False}

    return {
        "authenticated": True,
        "user": {
            "id": str(user["id"]),
            "email": user["email"],
            "role": user["role"],
            "email_verified": bool(user.get("email_verified")),
            "user_metadata": {
                "full_name": user.get("full_name") or "",
                "mobile": user.get("mobile"),
            },
        },
    }


@router.post("/refresh")
def refresh_session(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    conn: psycopg.Connection = Depends(get_db),
):
    """Rotate refresh token stored in PostgreSQL and issue fresh HttpOnly cookies."""
    raw_token = request.cookies.get(settings.refresh_cookie_name) or (
        body.refresh_token if body else None
    )
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh session.",
        )

    token_hash = hash_refresh_token(raw_token)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT rt.id, rt.user_id, rt.revoked, rt.expires_at,
                   u.email, u.full_name, u.mobile, u.role,
                   u.account_status, u.email_verified, u.deleted_at, u.status
              FROM public.refresh_tokens rt
              JOIN public.users u ON u.id = rt.user_id
             WHERE rt.token_hash = %s
             LIMIT 1
               FOR UPDATE OF rt
            """,
            (token_hash,),
        )
        row = cur.fetchone()

    if not row:
        clear_session_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )

    if row["revoked"]:
        # Reuse detected: revoke every active refresh token for this user.
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.refresh_tokens SET revoked = TRUE WHERE user_id = %s",
                (row["user_id"],),
            )
        conn.commit()
        clear_session_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected. Please sign in again.",
        )

    if (
        datetime.now(timezone.utc) > row["expires_at"]
        or row["deleted_at"] is not None
        or row["account_status"] != "active"
        or row["status"] != "active"
    ):
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.refresh_tokens SET revoked = TRUE WHERE id = %s",
                (row["id"],),
            )
        conn.commit()
        clear_session_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )

    new_access, expires_in = create_access_token(
        user_id=str(row["user_id"]),
        email=str(row["email"]),
        role=str(row.get("role", "user")),
    )
    new_raw_refresh = generate_refresh_token()
    new_hash = hash_refresh_token(new_raw_refresh)
    new_expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.refresh_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (row["user_id"], new_hash, new_expires_at),
        )
        new_rt = cur.fetchone()
        cur.execute(
            """
            UPDATE public.refresh_tokens
               SET revoked = TRUE, replaced_by_id = %s
             WHERE id = %s
            """,
            (new_rt["id"], row["id"]),
        )
    conn.commit()

    set_session_cookies(response, new_access, new_raw_refresh)
    return {
        "success": True,
        "authenticated": True,
        "expires_in": expires_in,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    conn: psycopg.Connection = Depends(get_db),
):
    """Revoke refresh token in PostgreSQL and clear HttpOnly cookies."""
    raw_refresh = request.cookies.get(settings.refresh_cookie_name) or (
        body.refresh_token if body else None
    )
    if raw_refresh:
        token_hash = hash_refresh_token(raw_refresh)
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.refresh_tokens SET revoked = TRUE WHERE token_hash = %s",
                (token_hash,),
            )
        conn.commit()

    clear_session_cookies(response)
    return {"success": True}


@router.post("/forgot-password")
def forgot_password(
    data: ForgotPasswordRequest,
    conn: psycopg.Connection = Depends(get_db),
):
    """Send a self-hosted signed password reset link via Gmail SMTP."""
    email = str(data.email).strip().lower()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, full_name
              FROM public.users
             WHERE LOWER(email) = LOWER(%s)
               AND deleted_at IS NULL
               AND account_status = 'active'
               AND status = 'active'
             LIMIT 1
            """,
            (email,),
        )
        user = cur.fetchone()

    if user:
        reset_token = create_reset_token(str(user["id"]), str(user["email"]))
        reset_link = f"{settings.frontend_url}/reset-password.html?token={reset_token}"
        name = user.get("full_name") or "there"
        body_text = (
            f"Hi {name},\n\n"
            "We received a request to reset your Beevolve password.\n\n"
            f"Open this link to set a new password (valid for {settings.password_reset_expire_minutes} minutes):\n"
            f"{reset_link}\n\n"
            "If you did not request this change, you can safely ignore this email.\n\n"
            "Regards,\nBeevolve Team\n"
        )
        try:
            _send_smtp_email(email, "Reset your Beevolve password", body_text)
        except Exception as exc:
            logger.exception("Forgot password SMTP error for %s", email)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to send password reset email right now.",
            ) from exc

    return {
        "success": True,
        "message": "If the account exists, a password reset email has been sent.",
    }


@router.post("/oauth/exchange")
def oauth_exchange(data: OAuthExchangeRequest, response: Response):
    """Convert a password-reset or access token into HttpOnly cookies."""
    # Try dedicated password-reset token first so reset links never grant API login cookies.
    try:
        decode_reset_token(data.access_token)
        response.set_cookie(
            settings.reset_cookie_name,
            data.access_token,
            max_age=settings.password_reset_expire_minutes * 60,
            **_cookie_kwargs(),
        )
        return {"success": True, "authenticated": False, "reset_session": True}
    except TokenError:
        pass

    try:
        decode_access_token(data.access_token)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is invalid or expired.",
        ) from exc

    set_session_cookies(response, data.access_token, None)
    return {"success": True, "authenticated": True}


@router.post("/update-password")
def update_password(
    data: UpdatePasswordRequest,
    request: Request,
    response: Response,
    conn: psycopg.Connection = Depends(get_db),
):
    """Update password in PostgreSQL using a reset session or active user session."""
    pw_error = validate_password_strength(data.password)
    if pw_error:
        raise HTTPException(
            status_code=422,
            detail=pw_error,
        )

    user_id: str | None = None
    reset_token = data.token or request.cookies.get(settings.reset_cookie_name)
    if reset_token:
        try:
            payload = decode_reset_token(reset_token)
            user_id = str(payload["sub"])
        except TokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Password reset session expired. Please request a new reset email.",
            ) from exc
    else:
        access_token = extract_access_token(request)
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Password reset session expired. Please request a new reset email.",
            )
        try:
            payload = decode_access_token(access_token)
            user_id = str(payload["sub"])
        except TokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired. Please sign in again.",
            ) from exc

    user = _fetch_active_user_by_id(conn, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found or inactive.",
        )

    new_hash = hash_password(data.password)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.users SET password_hash = %s WHERE id = %s",
            (new_hash, user_id),
        )
        cur.execute(
            "UPDATE public.refresh_tokens SET revoked = TRUE WHERE user_id = %s",
            (user_id,),
        )
    _log_activity(conn, user_id, "password_updated", entity_id=user_id)
    conn.commit()

    response.delete_cookie(settings.reset_cookie_name, path="/")
    return {"success": True, "message": "Password updated successfully."}


def _upsert_google_user(
    conn: psycopg.Connection,
    *,
    google_sub: str,
    email: str,
    full_name: str,
    email_verified: bool,
) -> dict[str, Any]:
    """Find or create user + oauth_accounts row inside PostgreSQL."""
    normalized_email = email.strip().lower()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.email, u.full_name, u.mobile, u.role,
                   u.account_status, u.email_verified, u.deleted_at, u.status
              FROM public.oauth_accounts oa
              JOIN public.users u ON u.id = oa.user_id
             WHERE oa.provider = 'google'
               AND oa.provider_user_id = %s
             LIMIT 1
            """,
            (google_sub,),
        )
        user = cur.fetchone()

        if user:
            if (
                user["deleted_at"] is not None
                or user["account_status"] != "active"
                or user["status"] != "active"
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is suspended or deleted.",
                )
            return user

        cur.execute(
            """
            SELECT id, email, full_name, mobile, role,
                   account_status, email_verified, deleted_at, status
              FROM public.users
             WHERE LOWER(email) = LOWER(%s)
             LIMIT 1
            """,
            (normalized_email,),
        )
        user = cur.fetchone()

        if user:
            if (
                user["deleted_at"] is not None
                or user["account_status"] != "active"
                or user["status"] != "active"
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is suspended or deleted.",
                )
            if (email_verified and not user["email_verified"]) or (
                full_name and not user.get("full_name")
            ):
                cur.execute(
                    """
                    UPDATE public.users
                       SET email_verified = email_verified OR %s,
                           full_name = CASE WHEN full_name = '' THEN %s ELSE full_name END
                     WHERE id = %s
                    RETURNING id, email, full_name, mobile, role,
                              account_status, email_verified, status
                    """,
                    (email_verified, full_name, user["id"]),
                )
                user = cur.fetchone()
        else:
            cur.execute(
                """
                INSERT INTO public.users
                  (email, full_name, password_hash, role, email_verified)
                VALUES (%s, %s, NULL, 'user', %s)
                RETURNING id, email, full_name, mobile, role,
                          account_status, email_verified, status
                """,
                (normalized_email, full_name, email_verified),
            )
            user = cur.fetchone()

        cur.execute(
            """
            INSERT INTO public.oauth_accounts (user_id, provider, provider_user_id)
            VALUES (%s, 'google', %s)
            ON CONFLICT (provider, provider_user_id) DO NOTHING
            """,
            (user["id"], google_sub),
        )
    return user


def _verify_google_id_token_claims(raw_id_token: str) -> dict[str, Any]:
    if not settings.google_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GOOGLE_CLIENT_ID is not configured in Backend/.env.",
        )
    try:
        claims = google_id_token.verify_oauth2_token(
            raw_id_token,
            google_requests.Request(),
            settings.google_client_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google ID token: {exc}",
        ) from exc

    if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token issuer.",
        )
    if not claims.get("sub") or not claims.get("email"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token is missing required user identity fields.",
        )
    return claims


@router.get("/oauth/google")
def google_oauth():
    """Return Google OAuth 2.0 consent URL for the frontend redirect flow."""
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured in Backend/.env.",
        )

    params = urlencode(
        {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": settings.google_scopes,
            "state": create_oauth_state("google"),
            "access_type": "offline",
            "prompt": "select_account",
        }
    )
    return {"url": f"{settings.google_auth_url}?{params}"}


@router.get("/oauth/google/callback")
def google_oauth_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    conn: psycopg.Connection = Depends(get_db),
):
    """Handle Google OAuth redirect, persist user/oauth_account in PostgreSQL, set HttpOnly cookies."""
    if error or not code or not state or not verify_oauth_state(state, "google"):
        return RedirectResponse(
            url=f"{settings.frontend_url}/index.html?oauth_error=google_auth_failed",
            status_code=status.HTTP_302_FOUND,
        )

    try:
        token_resp = httpx.post(
            settings.google_token_url,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=15.0,
        )
        token_data = token_resp.json()
    except Exception:
        logger.exception("Google token exchange request failed")
        return RedirectResponse(
            url=f"{settings.frontend_url}/index.html?oauth_error=google_exchange_failed",
            status_code=status.HTTP_302_FOUND,
        )

    if token_resp.status_code >= 400 or not token_data.get("id_token"):
        logger.warning("Google token exchange error: %s", token_data)
        return RedirectResponse(
            url=f"{settings.frontend_url}/index.html?oauth_error=google_exchange_failed",
            status_code=status.HTTP_302_FOUND,
        )

    claims = _verify_google_id_token_claims(token_data["id_token"])
    user = _upsert_google_user(
        conn,
        google_sub=str(claims["sub"]),
        email=str(claims["email"]),
        full_name=str(claims.get("name") or ""),
        email_verified=bool(claims.get("email_verified", False)),
    )
    access_token, raw_refresh, _ = _issue_session_tokens(conn, user)
    _log_activity(conn, str(user["id"]), "oauth_google_login", entity_id=str(user["id"]))
    conn.commit()

    redirect = RedirectResponse(
        url=f"{settings.frontend_url}/dashboard.html",
        status_code=status.HTTP_302_FOUND,
    )
    set_session_cookies(redirect, access_token, raw_refresh)
    return redirect


@router.post("/google")
def google_id_token_login(
    data: GoogleIdTokenRequest,
    response: Response,
    conn: psycopg.Connection = Depends(get_db),
):
    """Verify a Google ID token directly (Postman / One Tap) and set HttpOnly cookies."""
    claims = _verify_google_id_token_claims(data.id_token)
    user = _upsert_google_user(
        conn,
        google_sub=str(claims["sub"]),
        email=str(claims["email"]),
        full_name=str(claims.get("name") or ""),
        email_verified=bool(claims.get("email_verified", False)),
    )
    access_token, raw_refresh, expires_in = _issue_session_tokens(conn, user)
    _log_activity(conn, str(user["id"]), "oauth_google_login", entity_id=str(user["id"]))
    conn.commit()

    set_session_cookies(response, access_token, raw_refresh)
    return {
        "success": True,
        "authenticated": True,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": _serialize_user(user),
    }


@router.get("/oauth/microsoft")
def microsoft_oauth():
    """Explicitly report that Microsoft OAuth is not configured after Supabase removal."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Microsoft OAuth is not configured yet in standalone PostgreSQL mode. "
            "Please sign in with email or Google."
        ),
    )


@router.get("/profile")
def profile(
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Return the logged-in user's profile row from PostgreSQL."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, full_name, mobile, role, email_verified,
                   created_date AS created_at, updated_date AS updated_at
              FROM public.users
             WHERE id = %s
             LIMIT 1
            """,
            (user_id,),
        )
        row = cur.fetchone()

    if not row:
        return {"profile": None}

    return {
        "profile": {
            "id": str(row["id"]),
            "email": row["email"],
            "full_name": row["full_name"],
            "mobile": row["mobile"],
            "role": row["role"],
            "email_verified": row["email_verified"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        }
    }



@router.put("/profile")
def update_profile(
    data: UpdateProfileRequest,
    user_id: str = Depends(get_current_user_id),
    conn: psycopg.Connection = Depends(get_db),
):
    """Update the authenticated user's profile in PostgreSQL."""

    normalized_email = str(data.email).strip().lower()
    full_name = data.full_name.strip()

    try:
        mobile = normalize_indian_mobile(data.mobile, required=False)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    with conn.cursor() as cur:
        # Check whether another user already uses this email or mobile.
        cur.execute(
            """
            SELECT id, email, mobile
              FROM public.users
             WHERE id <> %s
               AND (
                    LOWER(email) = LOWER(%s)
                    OR (
                        %s::text IS NOT NULL
                        AND mobile = %s::text
                    )
               )
             LIMIT 1
            """,
            (user_id, normalized_email, mobile, mobile),
        )

        conflict = cur.fetchone()

        if conflict:
            if str(conflict["email"]).lower() == normalized_email:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="That email address is already in use.",
                )

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="That mobile number is already in use.",
            )

        # Update the user's profile.
        cur.execute(
            """
            UPDATE public.users
               SET email = %s,
                   full_name = %s,
                   mobile = %s
             WHERE id = %s
            RETURNING id, email, full_name, mobile, role, email_verified,
                      created_date AS created_at, updated_date AS updated_at
            """,
            (normalized_email, full_name, mobile, user_id),
        )

        updated = cur.fetchone()

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found.",
        )

    _log_activity(conn, user_id, "profile_updated", entity_id=user_id)
    conn.commit()

    return {
        "success": True,
        "message": "Profile updated successfully.",
        "profile": {
            "id": str(updated["id"]),
            "email": updated["email"],
            "full_name": updated["full_name"],
            "mobile": updated["mobile"],
            "role": updated["role"],
            "email_verified": updated["email_verified"],
            "created_at": (
                updated["created_at"].isoformat()
                if updated["created_at"] else None
            ),
            "updated_at": (
                updated["updated_at"].isoformat()
                if updated["updated_at"] else None
            ),
        },
    }
