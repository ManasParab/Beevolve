"""Direct PostgreSQL connection helpers using pure-Python psycopg."""

from collections.abc import Generator
import glob
import os

from fastapi import HTTPException, status

# On Windows, help pure-Python psycopg locate PostgreSQL's libpq.dll automatically
# without triggering Application Control blocks on bundled binary wheels.
if os.name == "nt":
    for pg_bin in sorted(glob.glob(r"C:\Program Files\PostgreSQL\*\bin"), reverse=True):
        if os.path.isdir(pg_bin):
            os.environ["PATH"] = pg_bin + os.pathsep + os.environ.get("PATH", "")
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(pg_bin)

import psycopg  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

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
