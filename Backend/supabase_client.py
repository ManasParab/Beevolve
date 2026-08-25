import os
import httpx
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is missing from .env")
if not SUPABASE_ANON_KEY:
    raise RuntimeError("SUPABASE_ANON_KEY is missing from .env")

AUTH_URL = f"{SUPABASE_URL.rstrip('/')}/auth/v1"
REST_URL = f"{SUPABASE_URL.rstrip('/')}/rest/v1"

async def supabase_request(method: str, path: str, *, json=None, access_token=None, params=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.request(
            method,
            f"{AUTH_URL}/{path.lstrip('/')}",
            headers=headers,
            json=json,
            params=params,
        )
    return response

async def supabase_rest_request(method: str, path: str, *, json=None, access_token=None, params=None, extra_headers=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.request(
            method,
            f"{REST_URL}/{path.lstrip('/')}",
            headers=headers,
            json=json,
            params=params,
        )
    return response
