"""Password hashing, JWT session tokens, refresh token hashing, and OTP helpers."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets
import uuid

import bcrypt
import jwt

from config import settings


class TokenError(Exception):
    """Raised when a JWT or signed state token is missing, invalid, or expired."""


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt with configured salt rounds."""
    hashed = bcrypt.hashpw(
        plain_password.encode("utf-8"),
        bcrypt.gensalt(rounds=settings.bcrypt_rounds),
    )
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str | None) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> str | None:
    """Validate password complexity rules and return an error message if invalid."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if (
        not re.search(r"[A-Za-z]", password)
        or not re.search(r"[0-9]", password)
        or not re.search(r"[^A-Za-z0-9]", password)
    ):
        return "Password must include a letter, a number, and a symbol."
    return None


def normalize_indian_mobile(raw_mobile: str | None, *, required: bool = False) -> str | None:
    """Validate and normalize an Indian mobile number to +91XXXXXXXXXX."""
    cleaned = (raw_mobile or "").strip()
    if not cleaned:
        if required:
            raise ValueError("Please enter a valid 10-digit Indian mobile number.")
        return None

    digits = re.sub(r"\D", "", cleaned)
    if digits.startswith("0091") and len(digits) == 14:
        digits = digits[4:]
    elif digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]

    if not re.fullmatch(r"[6-9]\d{9}", digits):
        raise ValueError("Please enter a valid 10-digit Indian mobile number.")

    return "+91" + digits


def _encode_jwt(payload: dict, secret: str, expires_delta: timedelta) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    exp = now + expires_delta
    claims = {
        **payload,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(claims, secret, algorithm=settings.jwt_algorithm)
    return token, int(expires_delta.total_seconds())


def _decode_jwt(token: str, secret: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "exp", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Invalid authentication token.") from exc

    if payload.get("type") != expected_type:
        raise TokenError("Unexpected token type.")
    return payload


def create_access_token(user_id: str, email: str, role: str = "user") -> tuple[str, int]:
    """Create a short-lived signed JWT access token."""
    return _encode_jwt(
        {"sub": user_id, "email": email, "role": role, "type": "access"},
        settings.jwt_secret_key,
        timedelta(minutes=settings.access_token_expire_minutes),
    )


def decode_access_token(token: str) -> dict:
    """Decode and validate an access JWT."""
    return _decode_jwt(token, settings.jwt_secret_key, "access")


def create_reset_token(user_id: str, email: str) -> str:
    """Create a short-lived single-purpose password reset JWT."""
    token, _ = _encode_jwt(
        {"sub": user_id, "email": email, "type": "password_reset"},
        settings.jwt_secret_key,
        timedelta(minutes=settings.password_reset_expire_minutes),
    )
    return token


def decode_reset_token(token: str) -> dict:
    """Decode and validate a password reset JWT."""
    return _decode_jwt(token, settings.jwt_secret_key, "password_reset")


def create_oauth_state(provider: str) -> str:
    """Create a short-lived CSRF protection state token for OAuth redirects."""
    token, _ = _encode_jwt(
        {"sub": provider, "type": "oauth_state", "nonce": secrets.token_hex(12)},
        settings.jwt_secret_key,
        timedelta(minutes=settings.oauth_state_expire_minutes),
    )
    return token


def verify_oauth_state(state: str, provider: str) -> bool:
    """Verify OAuth state JWT matches expected provider and has not expired."""
    try:
        payload = _decode_jwt(state, settings.jwt_secret_key, "oauth_state")
    except TokenError:
        return False
    return payload.get("sub") == provider


def generate_refresh_token() -> str:
    """Generate a high-entropy opaque refresh token."""
    return secrets.token_urlsafe(48)


def hash_refresh_token(raw_token: str) -> str:
    """Compute keyed SHA-256 hash of a refresh token for PostgreSQL storage."""
    return hmac.new(
        settings.jwt_refresh_secret_key.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_email_otp() -> str:
    """Generate a 6-character alphanumeric OTP excluding ambiguous glyphs."""
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    numbers = "23456789"
    otp = [secrets.choice(letters), secrets.choice(numbers)]
    alphabet = letters + numbers
    otp.extend(secrets.choice(alphabet) for _ in range(4))
    secrets.SystemRandom().shuffle(otp)
    return "".join(otp)


def hash_email_otp(otp: str) -> str:
    """Hash a normalized OTP with EMAIL_OTP_PEPPER before storing."""
    normalized = otp.strip().upper()
    return hashlib.sha256(
        f"{settings.email_otp_pepper}:{normalized}".encode("utf-8")
    ).hexdigest()
