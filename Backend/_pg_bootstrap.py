"""Windows environment bootstrap for PostgreSQL / psycopg.

Ensures that PostgreSQL's official libpq.dll is discoverable via PATH and
os.add_dll_directory, and configures psycopg to use the pure-Python ctypes
implementation so Windows Application Control (Smart App Control / WDAC)
does not block execution of bundled binary wheels.
"""

from __future__ import annotations

import glob
import os

if os.name == "nt":
    # Search common PostgreSQL install locations (PostgreSQL 18, 17, 16, etc.)
    for pg_bin in sorted(glob.glob(r"C:\Program Files\PostgreSQL\*\bin"), reverse=True):
        if os.path.isdir(pg_bin):
            current_path = os.environ.get("PATH", "")
            if pg_bin not in current_path:
                os.environ["PATH"] = pg_bin + os.pathsep + current_path
            if hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(pg_bin)
                except OSError:
                    pass

    # Prefer python (ctypes) implementation when binary wheel is blocked by Application Control
    if "PSYCOPG_IMPL" not in os.environ:
        os.environ["PSYCOPG_IMPL"] = "python"
