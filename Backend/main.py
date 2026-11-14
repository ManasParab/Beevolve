"""Beevolve FastAPI entry point backed directly by PostgreSQL and HttpOnly cookies."""

from urllib.parse import urlparse

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
import _pg_bootstrap  # noqa: F401
import psycopg

from config import settings
from database import get_db
from routes.auth import router as auth_router
from routes.payments import router as payments_router
from routes.subscriptions import router as subscriptions_router
from routes.webhooks import router as webhooks_router

REQUIRED_TABLES = (
    "users",
    "mst_coupon",
    "mst_product",
    "mst_plan",
    "orders",
    "order_items",
    "subscriptions",
    "subscription_payments",
    "notifications",
    "otp_verifications",
    "refresh_tokens",
    "user_activity_log",
    "oauth_accounts",
    "webhook_events",
)

app = FastAPI(title=settings.app_name, version=settings.app_version)

origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
]
parsed_frontend = urlparse(settings.frontend_url)
if parsed_frontend.scheme and parsed_frontend.netloc:
    frontend_origin = f"{parsed_frontend.scheme}://{parsed_frontend.netloc}"
    if frontend_origin not in origins:
        origins.append(frontend_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(payments_router)
app.include_router(webhooks_router)
app.include_router(subscriptions_router)


@app.get("/")
def root():
    return {"message": "Beevolve API is running", "database": "postgresql"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/health/db")
def health_db(conn: psycopg.Connection = Depends(get_db)):
    """Verify PostgreSQL connectivity and presence of all 14 BeEvolve schema tables."""
    with conn.cursor() as cur:
        cur.execute("SELECT current_database() AS db_name")
        db_row = cur.fetchone()
        cur.execute(
            """
            SELECT tablename AS table_name
              FROM pg_catalog.pg_tables
             WHERE schemaname = 'public'
             ORDER BY tablename
            """
        )
        found = {
            row["table_name"]
            for row in cur.fetchall()
            if row["table_name"] in REQUIRED_TABLES
        }

    missing = [name for name in REQUIRED_TABLES if name not in found]
    return {
        "status": "ok" if not missing else "degraded",
        "database": db_row["db_name"] if db_row else None,
        "tables_expected": len(REQUIRED_TABLES),
        "tables_found": len(found),
        "missing_tables": missing,
    }
