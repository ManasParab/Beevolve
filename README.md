# Beevolve Authentication Module

## Project structure

- `Frontend/` — existing Beevolve UI, CSS, hero video and browser-side API calls.
- `Backend/` — FastAPI API and server-side Supabase connection.
- `supabase/schema.sql` — profiles table, RLS and signup trigger.

## Security architecture

The browser does **not** contain `SUPABASE_URL` or `SUPABASE_ANON_KEY` and does not initialize the Supabase JavaScript client.

Those values are stored only in:

`Backend/.env`

The browser communicates with FastAPI using `fetch()` and the backend communicates with Supabase.

Authentication sessions are stored in HttpOnly cookies so frontend JavaScript cannot read the access/refresh tokens.

## Local run

### Backend

Open a terminal in:

`Backend`

Create the uv virtual environment and install dependencies:

    uv venv
    .\.venv\Scripts\Activate.ps1
    uv pip install -r requirements.txt

If PowerShell blocks script activation, run this once in PowerShell:

    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

The backend reads Supabase settings from `Backend/.env`. Copy your project URL and anon/publishable key into that file before starting the API.

Start FastAPI:

    uv run uvicorn main:app --reload

You can also start it after activation with:

    python -m uvicorn main:app --reload

API:

    http://127.0.0.1:8000

Swagger:

    http://127.0.0.1:8000/docs

### Payments

Payment order creation and verification are part of the main backend under
`/api/payments`. Add the Razorpay test credentials to `Backend/.env` as
`RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET`. Keep this file private.

### Frontend

Use VS Code Live Server and open:

    http://127.0.0.1:5500/Frontend/index.html

After signing in, open **Explore services** from the dashboard. Each purchase
button opens the integrated checkout page at:

    http://127.0.0.1:5500/Frontend/checkout.html

The backend CORS configuration allows `127.0.0.1:5500` and `localhost:5500`.

## Authentication implemented

- Registration through FastAPI -> Supabase Auth
- Duplicate-account handling
- Email verification
- Login through FastAPI -> Supabase Auth
- HttpOnly access/refresh cookies
- Current-session check
- Refresh session
- Logout
- Forgot password
- Password reset page
- Google OAuth initiation
- Microsoft/Azure OAuth initiation
- OAuth callback token exchange into HttpOnly cookies
- Protected dashboard
- Profile retrieval through FastAPI -> Supabase PostgREST
- Dashboard service workspace with Resume Builder, Interview Prep and Notes Taker
- Individual career service checkout through Razorpay test mode

## Supabase setup

Run `supabase/schema.sql` in Supabase SQL Editor.

To get the values for `Backend/.env`, open your Supabase project at `https://app.supabase.com`, then go to **Project Settings -> API** (or **API Keys** in the newer dashboard). Copy **Project URL** into `SUPABASE_URL`. Copy the client-side **Publishable key** (or legacy **anon** key) into `SUPABASE_ANON_KEY`. Never put the `service_role` or secret key in this project or commit it.

For OAuth, enable Google and Microsoft/Azure providers in Supabase Authentication settings.

Add the local frontend callback URL to Supabase Redirect URLs:

    http://127.0.0.1:5500/Frontend/oauth-callback.html

For password reset:

    http://127.0.0.1:5500/Frontend/reset-password.html

Use the same URLs when deploying, replacing the local origin with the production frontend URL.

## Important

Do not commit `Backend/.env` to Git. The existing `.gitignore` excludes it.
