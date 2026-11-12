# BeEvolve Project — Complete File, API & Database Guide

This guide explains **every file in the project**, **every API endpoint**, and **all 14 PostgreSQL tables** in simple, clear language.

---

## 1. Big Picture: How the App Works

```text
Browser (Frontend on http://127.0.0.1:5500)
   │  Sends requests with HttpOnly Cookies (beevolve_access / beevolve_refresh)
   ▼
FastAPI Server (Backend on http://127.0.0.1:8000)
   │  Verifies passwords (bcrypt), signs/reads JWTs, runs business rules
   ▼
PostgreSQL Database (beevolve_auth on localhost:5432)
   └─ Stores all 14 tables (users, tokens, OTPs, orders, subscriptions, logs)
```

### External Services Used (Only 3)
1. **Gmail SMTP (`smtp.gmail.com`)** — Sends Email OTP verification codes and Forgot Password links. (OTP generation, hashing, and checking all happen in your own Backend + PostgreSQL.)
2. **Google OAuth 2.0** — Verifies a user's Google account when they click **Continue with Google**. Once verified, your Backend creates/loads the user in PostgreSQL and sets your own HttpOnly cookies.
3. **Razorpay** — Handles payment checkout and recurring autopay billing. Orders, coupons, and active subscriptions are stored in PostgreSQL.

*(Supabase Auth and Supabase PostgREST have been completely removed.)*

---

## 2. Folder & File Breakdown

### A. Backend Core Files (`Backend/`)

| File | What it does (in simple words) | Key Functions / Classes |
| :--- | :--- | :--- |
| **`Backend/main.py`** | Entry point of the FastAPI server. Enables CORS for `127.0.0.1:5500` and `localhost:5500`, plugs in all route files, and exposes health check URLs. | `root()` (`/`), `health()` (`/api/health`), `health_db()` (`/api/health/db` — checks PostgreSQL and verifies all 14 tables exist). |
| **`Backend/config.yml`** | Stores non-secret app rules in easy-to-edit YAML format: JWT lifetime (`15` min), refresh token lifetime (`7` days), `bcrypt_rounds` (`12`), login lockout (`5` attempts / `600` sec), `require_email_verification` (`false`), OTP rules, and Google OAuth URLs. | YAML configuration file read by `config.py`. |
| **`Backend/config.py`** | Combines non-secret settings from `config.yml` with secret credentials from `.env` into a single `settings` object used by the rest of the backend. | `Settings`, `load_settings()`. |
| **`Backend/.env`** | Private secrets file (never share or commit to Git): `DATABASE_URL`, `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SMTP_*`, `EMAIL_OTP_PEPPER`, and `RAZORPAY_*`. | Environment variables. |
| **`Backend/.env.example`** | Safe template showing which keys `Backend/.env` needs without any real passwords or secrets. | Reference template. |
| **`Backend/database.py`** | Connects directly to PostgreSQL using pure-Python `psycopg`. On Windows, automatically finds `C:\Program Files\PostgreSQL\*\bin` (`libpq.dll`) so imports work smoothly. | `normalized_dsn()`, `open_connection()`, `get_db()` (opens a DB connection per request, commits on success, rolls back on error, and closes cleanly). |
| **`Backend/security.py`** | Handles all password and token cryptography locally without any third-party auth service. | `hash_password()`, `verify_password()` (`bcrypt`), `validate_password_strength()`, `normalize_indian_mobile()` (`+91XXXXXXXXXX`), `create_access_token()`, `decode_access_token()`, `create_reset_token()`, `decode_reset_token()`, `create_oauth_state()`, `verify_oauth_state()`, `generate_refresh_token()`, `hash_refresh_token()`, `generate_email_otp()`, `hash_email_otp()`. |
| **`Backend/requirements.txt`** | Lists all Python packages required by the backend (`fastapi`, `uvicorn`, `psycopg`, `PyJWT`, `bcrypt`, `PyYAML`, `google-auth`, `httpx`, `python-dotenv`, `pydantic`, `razorpay`). | Package manifest. |
| **`Backend/supabase_client.py`** | Retired stub from before migration. Immediately raises `ImportError` if anything ever tries to import it, ensuring zero Supabase calls remain. | Retirement guard. |
| **`Backend/.gitignore`** | Tells Git to ignore `.env`, `__pycache__`, and local cache files so secrets never leak. | Git ignore rules. |
| **`Backend/tests/test_backend.py`** | Automated unit test suite verifying all auth, OTP, cookie, refresh rotation, Google OAuth, profile, payment, subscription, and webhook flows using an in-memory DB test double and mocked external APIs. | `InMemoryStore`, `FakeCursor`, `FakeConnection`, `TestBeEvolvePostgresBackend` (`test_01` through `test_05`). |

---

### B. Backend API Route Files (`Backend/routes/`)

#### 1. `Backend/routes/auth.py` — Authentication, OTP, Sessions, Profile & Google OAuth

**Internal Helpers (shared across routes):**
- `set_session_cookies()` / `clear_session_cookies()` — Writes or deletes `beevolve_access`, `beevolve_refresh`, and `beevolve_reset` **HttpOnly** cookies.
- `extract_access_token()` — Reads the JWT from the `beevolve_access` cookie first, or falls back to an `Authorization: Bearer <token>` header (helpful for Postman).
- `get_current_user()` / `get_current_user_id()` — Verifies the JWT, checks `public.users` to make sure the account is active and not deleted, and injects the user ID into protected routes.
- `_issue_session_tokens()` — Creates a short-lived JWT access token + a random refresh token, stores the hashed refresh token in `public.refresh_tokens`, and returns them.
- `_upsert_google_user()` — Finds an existing user by Google `sub` (`oauth_accounts`) or email (`users`), creates a new user row if needed, and links Google in `oauth_accounts`.
- `_log_activity()` — Records key actions (`user_registered`, `email_verified`, `user_logged_in`, `oauth_google_login`, `password_updated`, `profile_updated`) in `public.user_activity_log`.

**API Endpoints:**

| Method & URL | Function | What it does |
| :--- | :--- | :--- |
| `POST /api/auth/register` | `register_user` | Validates Terms acceptance, password match (`confirm_password`), password strength, and 10-digit Indian mobile (`+91`). Checks `users` for duplicate email/mobile (`409`). Hashes password with `bcrypt`, saves user (`201 Created`), and returns `user_id` for the OTP screen. |
| `POST /api/auth/email-otp/send` | `send_email_otp` | Enforces resend cooldown, creates a 6-character code, stores its salted SHA-256 hash in `otp_verifications`, and emails it via Gmail SMTP. |
| `POST /api/auth/email-otp/verify` | `verify_email_otp` | Checks OTP expiry and max wrong attempts (`5`), verifies hash with constant-time compare, marks `users.email_verified = TRUE`, and deletes the used OTP. |
| `POST /api/auth/login` | `login_user` | Enforces 5-attempt / 10-minute brute-force lockout (`429`), checks `bcrypt` password hash against `users.password_hash`, creates JWT + refresh token in `refresh_tokens`, and sets HttpOnly `beevolve_access` & `beevolve_refresh` cookies. |
| `GET /api/auth/me` | `current_user` | Checks the caller's cookie/Bearer JWT without raising errors for guests; returns `{authenticated: false}` or `{authenticated: true, user: {...}}` for page-load checks. |
| `POST /api/auth/refresh` | `refresh_session` | Reads `beevolve_refresh` cookie (or body token), checks `refresh_tokens`, detects reuse (if a revoked token is replayed, revokes **all** sessions for that user!), otherwise issues a brand-new access + refresh token pair and rotates the DB record. |
| `POST /api/auth/logout` | `logout` | Marks the refresh token `revoked = TRUE` in `refresh_tokens` and clears all auth cookies. |
| `POST /api/auth/forgot-password` | `forgot_password` | If the email belongs to an active user, creates a 30-minute single-purpose `password_reset` JWT and sends `reset-password.html?token=...` via Gmail SMTP. |
| `POST /api/auth/oauth/exchange` | `oauth_exchange` | Validates a `password_reset` token (sets isolated `beevolve_reset` HttpOnly cookie so reset links can't be used as login cookies) or a valid access token. |
| `POST /api/auth/update-password` | `update_password` | Accepts a reset cookie/token or logged-in session, validates password strength, updates `users.password_hash` with `bcrypt`, and revokes old refresh tokens. |
| `GET /api/auth/oauth/google` | `google_oauth` | Builds and returns the Google consent screen URL with signed CSRF `state` and `redirect_uri` pointing to `/api/auth/oauth/google/callback`. |
| `GET /api/auth/oauth/google/callback` | `google_oauth_callback` | Receives Google's `code` & `state`, exchanges the code for Google's `id_token`, verifies it, saves/links the user in `users` + `oauth_accounts`, sets HttpOnly cookies, and redirects to `dashboard.html`. |
| `POST /api/auth/google` | `google_id_token_login` | Direct API/Postman login endpoint that accepts a Google `id_token`, verifies it, upserts the user, and sets HttpOnly cookies. |
| `GET /api/auth/oauth/microsoft` | `microsoft_oauth` | Returns HTTP `501` explaining Microsoft OAuth is not configured after removing Supabase. |
| `GET /api/auth/profile` | `profile` | Returns the logged-in user's profile row (`id`, `email`, `full_name`, `mobile`, `role`, timestamps) from `public.users`. |
| `PUT /api/auth/profile` | `update_profile` | Validates Indian mobile & uniqueness (`409` on duplicate email/mobile) and updates `email`, `full_name`, and `mobile` in `public.users`. |

---

#### 2. `Backend/routes/payments.py` — One-Time Razorpay Checkout

| Method & URL | Function | What it does |
| :--- | :--- | :--- |
| `POST /api/payments/create-order` | `create_order` | Looks up the product & plan price from `mst_product` + `mst_plan`, validates any optional coupon in `mst_coupon` (dates, redemption limits, percent/flat discount), creates the Razorpay order, and saves `orders` + `order_items` inside one PostgreSQL transaction. |
| `POST /api/payments/verify` | `verify_payment` | Confirms the order belongs to the logged-in user, verifies Razorpay's HMAC signature, fetches payment status & amount from Razorpay, and either calls PostgreSQL function `public.apply_payment_success(...)` (if `captured`) or marks `payment_status = 'submitted'` (if `authorized`). |

---

#### 3. `Backend/routes/subscriptions.py` — Recurring Autopay & Access Checks

| Method & URL | Function | What it does |
| :--- | :--- | :--- |
| `POST /api/subscriptions/create` | `create_subscription` | Looks up an autopay-enabled plan (`provider_plan_id IS NOT NULL`) by `plan_id` or `service` fallback, records an `e-mandate` row in `orders` + `order_items`, and creates a Razorpay subscription returning its `short_url`. |
| `GET /api/subscriptions/me` | `get_my_subscriptions` | Loads all subscriptions for the logged-in user joined with `mst_plan` and `mst_product` so `dashboard.html` can show each service name, status, amount, start/expiry dates, and auto-renew state. |
| `GET /api/subscriptions/access/{product_id}` | `check_product_access` | Checks `public.subscriptions` to return `{has_access: true/false}` based on active status and `starts_at <= now < expires_at`. |

---

#### 4. `Backend/routes/webhooks.py` — Razorpay Async Webhooks

| Method & URL / Helper | Function | What it does |
| :--- | :--- | :--- |
| `POST /api/webhooks/razorpay` | `razorpay_webhook` | Verifies `X-Razorpay-Signature` HMAC-SHA256, calls `public.register_webhook_event(...)` to skip duplicate webhook deliveries, dispatches the event, and marks `webhook_events.processed_at`. If processing fails, deletes the deduplication row so Razorpay can retry safely. |
| Helper | `dispatch_event` | Routes events to PostgreSQL: `payment.captured` -> `apply_payment_success`, `payment.authorized` -> `UPDATE orders`, `payment.failed` -> `apply_payment_failure`, `subscription.charged` -> `apply_subscription_charged`, and `subscription.authenticated/activated/pending/halted/cancelled/completed` -> `apply_subscription_status`. |

---

### C. Database SQL Files (`database/` and `supabase/`)

| File | What it does |
| :--- | :--- |
| **`database/02_beevolve_postgres_standalone.sql`** | **Current active schema file** for standalone PostgreSQL 18. Creates `citext`, `user_role` enum, `set_audit_fields()` trigger function, all **14 tables**, indexes, audit triggers, all **5 payment/webhook PL/pgSQL functions**, and seed products & plans matching `Frontend/subscriptions.html`. |
| `database/01_beevolve_create.sql` | Original Supabase-coupled 14-table schema (used `auth.users`, `auth.uid()`, and Supabase RLS roles). Kept only as historical reference. |
| `database/02_beevolve_alter_existing.sql` | Legacy Supabase migration script that copied `public.profiles` + `auth.users` into `public.users`. Not needed in standalone PostgreSQL. |
| `database/03_beevolve_verify_and_tests.sql` | Legacy SQL verification & rollback test script for inspecting the 14 tables and testing PL/pgSQL functions inside SQL Editor. |
| `supabase/schema.sql` | Very first Supabase schema creating only the old `public.profiles` table. Historical reference only. |

---

### D. Frontend Files (`Frontend/`)

| File | What it does (in simple words) |
| :--- | :--- |
| **`Frontend/index.html`** | Main login & signup screen: Login tab, Create Account tab (Name, Mobile, Email, Password, Confirm Password, Terms checkbox), Forgot Password form, Gmail 6-character OTP verification box, and Google / Microsoft buttons. |
| **`Frontend/js/auth.js`** | Frontend controller for `index.html`. Validates forms in the browser, sends `fetch(..., { credentials: "include" })` requests to `http://127.0.0.1:8000/api/auth/*`, manages OTP cooldown timer, handles Google OAuth redirects/errors, and redirects signed-in users to `dashboard.html`. |
| **`Frontend/dashboard.html`** | Protected user workspace. Calls `/api/auth/me`, `/api/subscriptions/me`, and `/api/auth/profile` on load; displays purchased services (`Career Toolkit`, etc.), lets users edit and save their name/email/mobile (`PUT /api/auth/profile`), provides Resume Builder / Interview Prep / Notes Taker workspace cards, and handles Logout. |
| **`Frontend/subscriptions.html`** | Catalog of paid services (`Career Toolkit` Rs. 499, `Portfolio Review` Rs. 299, `Career Roadmap` Rs. 199). Clicking Buy opens `checkout.html` with the selected service, amount, and plan ID. |
| **`Frontend/checkout.html`** | Payment screen. Supports both **One-Time Payment** (`/api/payments/create-order` + Razorpay popup + `/api/payments/verify`) and optional **Autopay** (`/api/subscriptions/create` redirect). |
| **`Frontend/reset-password.html`** | Password reset form reached from the email link (`?token=...`). Sends the reset token once to `/api/auth/oauth/exchange` to receive an HttpOnly `beevolve_reset` cookie, then posts the new password to `/api/auth/update-password`. |
| **`Frontend/oauth-callback.html`** | Legacy implicit-grant callback page from Supabase OAuth. (Direct Google OAuth now sets HttpOnly cookies on the backend callback and lands directly on `dashboard.html`.) |
| **`Frontend/css/styles.css`** | All styling, layout, toasts, responsive grids, and typography across every HTML page. |
| **`Frontend/assets/hero.mp4`** | Background hero video displayed on the authentication page. |

---

### E. Other Repository Files

| File / Folder | What it does |
| :--- | :--- |
| `README.md` | Original repository README describing the folder layout and local URLs (written before the switch from Supabase to standalone PostgreSQL). |
| `postman/` | Local Postman collections and environment YAML files stored in the repository for API testing (`Register`, `Login`, `Refresh`, `Google Auth`, `Health`, etc.). |

---

## 3. All 14 PostgreSQL Tables (`beevolve_auth` -> `public`)

1. **`users`** — Stores every user account (`id`, `email`, `full_name`, `mobile`, `password_hash`, `role`, `account_status`, `email_verified`, `mfa_enabled`, `deleted_at`, audit columns).
2. **`oauth_accounts`** — Links external logins like Google (`provider = 'google'`, `provider_user_id` = Google `sub`) to `users.id`.
3. **`refresh_tokens`** — Stores SHA-256 hashes of issued refresh tokens (`revoked`, `replaced_by_id`, `expires_at`) for rotation and reuse detection.
4. **`otp_verifications`** — Stores salted SHA-256 hashes of temporary 6-character email OTP codes (`purpose`, `attempts`, `expires_at`).
5. **`user_activity_log`** — Audit trail of user events (register, email verification, logins, password updates, profile updates).
6. **`mst_product`** — Master list of BeEvolve services (`Career Toolkit`, `Portfolio Review`, `Career Roadmap`, `Beevolve Premium Plan`).
7. **`mst_plan`** — Pricing plans (`amount` in paise, `currency`, `plan_interval`, `duration_days`, optional Razorpay `provider_plan_id`) linked to `mst_product`.
8. **`mst_coupon`** — Discount coupons (`code`, `percent` or `flat`, dates, `max_redemptions`, `times_redeemed`).
9. **`orders`** — Payment orders (`order_status`: `pending`/`placed`/`failed`, `payment_status`: `initiated`/`submitted`/`credited`/`debited`, Razorpay IDs).
10. **`order_items`** — Line items linking each `order` to the `mst_plan` being purchased.
11. **`subscriptions`** — Active or historical user service access (`starts_at`, `expires_at`, `auto_renew`, `subscription_status`, Razorpay subscription metadata).
12. **`subscription_payments`** — Individual recurring charge records tied to a subscription.
13. **`notifications`** — Notification delivery tracking per user (`channel`, `sent_at`, `delivery_status`).
14. **`webhook_events`** — Deduplication log of incoming Razorpay webhooks (`event_id`, `event_type`, `payload`, `processed_at`).

---

## 4. Quick Start Reference

1. **Start Backend** (from `Backend/`):
   ```powershell
   python -m uvicorn main:app --reload
   ```
2. **Verify DB Connection:** Open `http://127.0.0.1:8000/api/health/db` (should show `"status": "ok"` and `"tables_found": 14`).
3. **Open Frontend:** Serve with VS Code Live Server and open `http://127.0.0.1:5500/Frontend/index.html`.
4. **Run Backend Automated Tests:**
   ```powershell
   python -m unittest discover -s tests -v
   ```
