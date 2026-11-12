"""Application configuration loaded from config.yml and .env."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv
import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yml"
ENV_PATH = BASE_DIR / ".env"


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    database_url: str

    jwt_secret_key: str
    jwt_refresh_secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    password_reset_expire_minutes: int
    oauth_state_expire_minutes: int
    bcrypt_rounds: int
    require_email_verification: bool
    login_max_attempts: int
    login_lockout_seconds: int

    frontend_url: str
    backend_url: str
    cookie_secure: bool
    access_cookie_name: str
    refresh_cookie_name: str
    reset_cookie_name: str
    cookie_samesite: str

    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_from_email: str
    smtp_from_name: str
    email_otp_expiry_minutes: int
    email_otp_max_attempts: int
    email_otp_resend_seconds: int
    email_otp_pepper: str

    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    google_token_url: str
    google_auth_url: str
    google_userinfo_url: str
    google_scopes: str

    razorpay_key_id: str
    razorpay_key_secret: str
    razorpay_webhook_secret: str


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    return int(raw) if raw else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    """Load non-secret settings from config.yml and secrets/overrides from .env."""
    load_dotenv(ENV_PATH)

    raw_cfg: dict = {}
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open("r", encoding="utf-8") as fh:
            raw_cfg = yaml.safe_load(fh) or {}

    app_cfg = raw_cfg.get("app", {})
    auth_cfg = raw_cfg.get("auth", {})
    otp_cfg = raw_cfg.get("otp", {})
    google_cfg = raw_cfg.get("google_oauth", {})

    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL is missing from Backend/.env")

    jwt_secret_key = os.getenv("JWT_SECRET_KEY", "").strip()
    if not jwt_secret_key:
        raise RuntimeError("JWT_SECRET_KEY is missing from Backend/.env")

    jwt_refresh_secret_key = (
        os.getenv("JWT_REFRESH_SECRET_KEY", "").strip() or jwt_secret_key
    )

    backend_url = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").strip().rstrip("/")
    frontend_url = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500/Frontend").strip().rstrip("/")
    smtp_username = os.getenv("SMTP_USERNAME", "").strip()
    smtp_from_email = os.getenv("SMTP_FROM_EMAIL", "").strip() or smtp_username

    google_redirect_uri = (
        os.getenv("GOOGLE_REDIRECT_URI", "").strip()
        or str(google_cfg.get("redirect_uri", "")).strip()
        or f"{backend_url}/api/auth/oauth/google/callback"
    )

    return Settings(
        app_name=str(app_cfg.get("name", "BeEvolve API")),
        app_version=str(app_cfg.get("version", "2.0.0")),
        database_url=database_url,
        jwt_secret_key=jwt_secret_key,
        jwt_refresh_secret_key=jwt_refresh_secret_key,
        jwt_algorithm=os.getenv("JWT_ALGORITHM", str(auth_cfg.get("jwt_algorithm", "HS256"))).strip(),
        access_token_expire_minutes=_env_int(
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            int(auth_cfg.get("access_token_expire_minutes", 15)),
        ),
        refresh_token_expire_days=_env_int(
            "REFRESH_TOKEN_EXPIRE_DAYS",
            int(auth_cfg.get("refresh_token_expire_days", 7)),
        ),
        password_reset_expire_minutes=int(auth_cfg.get("password_reset_expire_minutes", 30)),
        oauth_state_expire_minutes=int(auth_cfg.get("oauth_state_expire_minutes", 10)),
        bcrypt_rounds=int(auth_cfg.get("bcrypt_rounds", 12)),
        require_email_verification=_env_bool(
            "REQUIRE_EMAIL_VERIFICATION",
            bool(auth_cfg.get("require_email_verification", False)),
        ),
        login_max_attempts=int(auth_cfg.get("login_max_attempts", 5)),
        login_lockout_seconds=int(auth_cfg.get("login_lockout_seconds", 600)),
        frontend_url=frontend_url,
        backend_url=backend_url,
        cookie_secure=_env_bool("COOKIE_SECURE", False),
        access_cookie_name=str(auth_cfg.get("access_cookie_name", "beevolve_access")),
        refresh_cookie_name=str(auth_cfg.get("refresh_cookie_name", "beevolve_refresh")),
        reset_cookie_name="beevolve_reset",
        cookie_samesite=str(auth_cfg.get("cookie_samesite", "lax")),
        smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com").strip(),
        smtp_port=_env_int("SMTP_PORT", 587),
        smtp_username=smtp_username,
        smtp_password=os.getenv("SMTP_PASSWORD", "").strip(),
        smtp_from_email=smtp_from_email,
        smtp_from_name=os.getenv("SMTP_FROM_NAME", "Beevolve").strip(),
        email_otp_expiry_minutes=_env_int(
            "EMAIL_OTP_EXPIRY_MINUTES",
            int(otp_cfg.get("expiry_minutes", 10)),
        ),
        email_otp_max_attempts=_env_int(
            "EMAIL_OTP_MAX_ATTEMPTS",
            int(otp_cfg.get("max_attempts", 5)),
        ),
        email_otp_resend_seconds=_env_int(
            "EMAIL_OTP_RESEND_SECONDS",
            int(otp_cfg.get("resend_seconds", 60)),
        ),
        email_otp_pepper=os.getenv("EMAIL_OTP_PEPPER", "").strip() or jwt_secret_key,
        google_client_id=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
        google_redirect_uri=google_redirect_uri,
        google_token_url=str(google_cfg.get("token_url", "https://oauth2.googleapis.com/token")),
        google_auth_url=str(google_cfg.get("auth_url", "https://accounts.google.com/o/oauth2/v2/auth")),
        google_userinfo_url=str(google_cfg.get("userinfo_url", "https://openidconnect.googleapis.com/v1/userinfo")),
        google_scopes=str(google_cfg.get("scopes", "openid email profile")),
        razorpay_key_id=os.getenv("RAZORPAY_KEY_ID", "").strip(),
        razorpay_key_secret=os.getenv("RAZORPAY_KEY_SECRET", "").strip(),
        razorpay_webhook_secret=os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip(),
    )


settings = load_settings()
