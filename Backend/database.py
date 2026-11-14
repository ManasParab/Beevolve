"""Direct PostgreSQL connection helpers using pure-Python psycopg."""

from collections.abc import Generator
import glob
import os

from fastapi import HTTPException, status

import _pg_bootstrap  # noqa: F401
import psycopg
from psycopg.rows import dict_row

from config import settings  # noqa: E402


def normalized_dsn() -> str:
    """Return a psycopg-compatible PostgreSQL DSN from DATABASE_URL."""
    dsn = settings.database_url.strip().strip('"').strip("'")
    if dsn.startswith("DATABASE_URL="):
        dsn = dsn[len("DATABASE_URL=") :].strip()
    if dsn.startswith("postgresql+psycopg://"):
        dsn = "postgresql://" + dsn[len("postgresql+psycopg://") :]
    return dsn


def open_connection() -> psycopg.Connection:
    """Open a new PostgreSQL connection with dictionary rows enabled."""
    try:
        return psycopg.connect(normalized_dsn(), row_factory=dict_row)
    except (psycopg.OperationalError, psycopg.ProgrammingError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Unable to connect to PostgreSQL. Verify PostgreSQL is running and "
                "DATABASE_URL in Backend/.env starts with postgresql://..."
            ),
        ) from exc


def get_db() -> Generator[psycopg.Connection, None, None]:
    """FastAPI dependency providing a request-scoped PostgreSQL connection."""
    conn = open_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        if not conn.closed:
            conn.rollback()
        raise
    finally:
        if not conn.closed:
            conn.close()
