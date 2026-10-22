import os
import httpx
from dotenv import load_dotenv

import logging
from fastapi import HTTPException

logger = logging.getLogger(__name__)

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_PUBLISHABLE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is missing from .env")

if not SUPABASE_PUBLISHABLE_KEY:
    raise RuntimeError("SUPABASE_PUBLISHABLE_KEY is missing from .env")

if not SUPABASE_SECRET_KEY:
    raise RuntimeError("SUPABASE_SECRET_KEY is missing from .env")


AUTH_URL = f"{SUPABASE_URL.rstrip('/')}/auth/v1"
REST_URL = f"{SUPABASE_URL.rstrip('/')}/rest/v1"


async def supabase_request(
    method: str,
    path: str,
    *,
    json=None,
    access_token=None,
    params=None
):
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
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


async def supabase_rest_request(
    method: str,
    path: str,
    *,
    json=None,
    access_token=None,
    params=None,
    extra_headers=None
):
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Content-Type": "application/json",
    }

    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    if extra_headers:
        headers.update(extra_headers)

    
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.request(
                method,
                f"{REST_URL}/{path.lstrip('/')}",
                headers=headers,
                json=json,
                params=params,
            )
        return response

    except httpx.TimeoutException as exc:
        logger.exception("Supabase request timed out")
        raise HTTPException(
            status_code=504,
            detail="The database service timed out.",
        ) from exc

    except httpx.RequestError as exc:
        logger.exception("Unable to connect to Supabase")
        raise HTTPException(
            status_code=502,
            detail="Unable to communicate with the database service.",
        ) from exc



async def supabase_rpc(name: str, payload: dict):
    return await supabase_rest_request(
        "POST",
        f"rpc/{name}",
        json=payload
    )
