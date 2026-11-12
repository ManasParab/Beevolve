"""Automated verification tests for PostgreSQL-migrated BeEvolve Backend."""

from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

from fastapi import HTTPException, Response
from starlette.requests import Request

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Configure deterministic test env defaults if running in an isolated CI environment.
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:test@localhost:5432/beevolve_auth")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-at-least-32-chars-long")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "test-refresh-secret-key-at-least-32-chars")
os.environ.setdefault("RAZORPAY_KEY_ID", "rzp_test_dummy_key")
os.environ.setdefault("RAZORPAY_KEY_SECRET", "dummy_razorpay_secret")
os.environ.setdefault("RAZORPAY_WEBHOOK_SECRET", "dummy_webhook_secret")
os.environ.setdefault("GOOGLE_CLIENT_ID", "dummy-google-client-id.apps.googleusercontent.com")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "dummy-google-client-secret")
os.environ.setdefault("SMTP_USERNAME", "noreply@example.com")
os.environ.setdefault("SMTP_PASSWORD", "dummy-smtp-password")
os.environ.setdefault("EMAIL_OTP_PEPPER", "dummy-otp-pepper")

import psycopg  # noqa: E402
from psycopg.errors import NoDataFound  # noqa: E402

import main  # noqa: E402
from routes import auth as auth_routes  # noqa: E402
from routes import payments as payment_routes  # noqa: E402
from routes import subscriptions as sub_routes  # noqa: E402
from routes import webhooks as webhook_routes  # noqa: E402
import security  # noqa: E402


class InMemoryStore:
    """In-memory relational state backing FakeCursor/FakeConnection for sandbox unit tests."""

    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.oauth_accounts: dict[tuple[str, str], dict] = {}
        self.refresh_tokens: dict[str, dict] = {}
        self.otp_verifications: list[dict] = []
        self.activity_log: list[dict] = []
        self.coupons: dict[str, dict] = {}
        self.products: dict[str, dict] = {}
        self.plans: dict[str, dict] = {}
        self.orders: dict[str, dict] = {}
        self.order_items: list[dict] = []
        self.subscriptions: dict[str, dict] = {}
        self.webhook_events: dict[str, dict] = {}
        self.function_calls: list[tuple[str, tuple]] = []

        # Seed products and plans mirroring 02_beevolve_postgres_standalone.sql
        toolkit_prod = str(uuid.uuid4())
        self.products[toolkit_prod] = {
            "id": toolkit_prod,
            "slug": "career-toolkit",
            "name": "Career Toolkit",
            "category": "career",
            "is_active": True,
            "status": "active",
        }
        self.plans["61af1c9e-ba0f-4a83-ac8d-e95773a13b04"] = {
            "id": "61af1c9e-ba0f-4a83-ac8d-e95773a13b04",
            "product_id": toolkit_prod,
            "plan_interval": "annual",
            "duration_days": 365,
            "amount": 100,
            "currency": "INR",
            "provider_plan_id": "plan_rzp_toolkit",
            "status": "active",
            "created_date": datetime.now(timezone.utc),
        }
        coupon_id = str(uuid.uuid4())
        self.coupons[coupon_id] = {
            "id": coupon_id,
            "code": "SAVE20",
            "discount_type": "percent",
            "discount_value": 20,
            "max_redemptions": 100,
            "times_redeemed": 0,
            "start_date": date.today() - timedelta(days=1),
            "expiry_date": date.today() + timedelta(days=30),
            "status": "active",
        }


class FakeCursor:
    """Executes parameterized SQL statements issued by BeEvolve route modules against InMemoryStore."""

    def __init__(self, store: InMemoryStore) -> None:
        self.store = store
        self._one = None
        self._many: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def fetchone(self):
        return self._one

    def fetchall(self):
        return list(self._many)

    def execute(self, sql: str, params=()):
        q = " ".join(sql.strip().split())
        self._one = None
        self._many = []

        # Health DB check
        if q.startswith("SELECT current_database()"):
            self._one = {"db_name": "beevolve_auth"}
            return
        if "FROM pg_catalog.pg_tables" in q:
            self._many = [{"table_name": name} for name in main.REQUIRED_TABLES]
            return

        # Users queries
        if "FROM public.users WHERE id = %s" in q and "deleted_at IS NULL" in q:
            uid = str(params[0])
            user = self.store.users.get(uid)
            if user and user["deleted_at"] is None and user["account_status"] == "active" and user["status"] == "active":
                self._one = dict(user)
            return

        if "FROM public.users WHERE id = %s LIMIT 1" in q:
            user = self.store.users.get(str(params[0]))
            if user:
                self._one = {
                    **user,
                    "created_at": user["created_date"],
                    "updated_at": user["updated_date"],
                }
            return

        if "SELECT email, mobile FROM public.users WHERE LOWER(email) = LOWER(%s) OR mobile = %s" in q:
            email, mobile = params[0].lower(), params[1]
            for u in self.store.users.values():
                if u["email"].lower() == email or (mobile and u["mobile"] == mobile):
                    self._one = {"email": u["email"], "mobile": u["mobile"]}
                    return
            return

        if "INSERT INTO public.users (email, full_name, mobile, password_hash" in q:
            email, full_name, mobile, pw_hash = params
            uid = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            row = {
                "id": uid,
                "email": email,
                "full_name": full_name,
                "mobile": mobile,
                "password_hash": pw_hash,
                "role": "user",
                "account_status": "active",
                "email_verified": False,
                "mfa_enabled": False,
                "deleted_at": None,
                "status": "active",
                "created_date": now,
                "updated_date": now,
            }
            self.store.users[uid] = row
            self._one = dict(row)
            return

        if "INSERT INTO public.users (email, full_name, password_hash, role, email_verified)" in q:
            email, full_name, email_verified = params
            uid = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            row = {
                "id": uid,
                "email": email,
                "full_name": full_name,
                "mobile": None,
                "password_hash": None,
                "role": "user",
                "account_status": "active",
                "email_verified": bool(email_verified),
                "mfa_enabled": False,
                "deleted_at": None,
                "status": "active",
                "created_date": now,
                "updated_date": now,
            }
            self.store.users[uid] = row
            self._one = dict(row)
            return

        if "FROM public.users WHERE LOWER(email) = LOWER(%s) AND deleted_at IS NULL" in q:
            email = params[0].lower()
            for u in self.store.users.values():
                if u["email"].lower() == email and u["deleted_at"] is None:
                    self._one = dict(u)
                    return
            return

        if "SELECT id, email, full_name, mobile, role, account_status, email_verified, deleted_at, status FROM public.users WHERE LOWER(email) = LOWER(%s)" in q:
            email = params[0].lower()
            for u in self.store.users.values():
                if u["email"].lower() == email:
                    self._one = dict(u)
                    return
            return

        if "UPDATE public.users SET email_verified = TRUE WHERE id = %s" in q:
            self.store.users[str(params[0])]["email_verified"] = True
            return

        if "UPDATE public.users SET password_hash = %s WHERE id = %s" in q:
            self.store.users[str(params[1])]["password_hash"] = params[0]
            return

        if "SELECT id, email, mobile FROM public.users WHERE id <> %s" in q:
            uid, email, _, mobile = str(params[0]), params[1].lower(), params[2], params[3]
            for u in self.store.users.values():
                if u["id"] != uid and (u["email"].lower() == email or (mobile and u["mobile"] == mobile)):
                    self._one = {"id": u["id"], "email": u["email"], "mobile": u["mobile"]}
                    return
            return

        if "UPDATE public.users SET email = %s, full_name = %s, mobile = %s WHERE id = %s" in q:
            email, full_name, mobile, uid = params
            u = self.store.users[str(uid)]
            u["email"] = email
            u["full_name"] = full_name
            u["mobile"] = mobile
            u["updated_date"] = datetime.now(timezone.utc)
            self._one = {**u, "created_at": u["created_date"], "updated_at": u["updated_date"]}
            return

        # OAuth accounts
        if "FROM public.oauth_accounts oa JOIN public.users u" in q:
            row = self.store.oauth_accounts.get(("google", params[0]))
            if row:
                self._one = dict(self.store.users[row["user_id"]])
            return

        if "INSERT INTO public.oauth_accounts" in q:
            uid, sub = str(params[0]), params[1]
            self.store.oauth_accounts.setdefault(("google", sub), {"user_id": uid, "provider": "google", "provider_user_id": sub})
            return

        # OTP verifications
        if "SELECT created_date FROM public.otp_verifications" in q:
            uid = str(params[0])
            matches = [o for o in self.store.otp_verifications if o["user_id"] == uid]
            if matches:
                self._one = {"created_date": matches[-1]["created_date"]}
            return

        if "SELECT id, otp_hash, expires_at, attempts FROM public.otp_verifications" in q:
            uid = str(params[0])
            matches = [o for o in self.store.otp_verifications if o["user_id"] == uid]
            if matches:
                self._one = dict(matches[-1])
            return

        if "DELETE FROM public.otp_verifications WHERE user_id = %s" in q:
            uid = str(params[0])
            self.store.otp_verifications = [o for o in self.store.otp_verifications if o["user_id"] != uid]
            return

        if "DELETE FROM public.otp_verifications WHERE id = %s" in q:
            oid = str(params[0])
            self.store.otp_verifications = [o for o in self.store.otp_verifications if o["id"] != oid]
            return

        if "UPDATE public.otp_verifications SET attempts = attempts + 1" in q:
            oid = str(params[0])
            for o in self.store.otp_verifications:
                if o["id"] == oid:
                    o["attempts"] += 1
            return

        if "INSERT INTO public.otp_verifications" in q:
            uid, otp_hash, expires_at = str(params[0]), params[1], params[2]
            self.store.otp_verifications.append({
                "id": str(uuid.uuid4()),
                "user_id": uid,
                "otp_hash": otp_hash,
                "purpose": "email_verification",
                "expires_at": expires_at,
                "attempts": 0,
                "created_date": datetime.now(timezone.utc),
            })
            return

        # Refresh tokens
        if "INSERT INTO public.refresh_tokens" in q:
            uid, token_hash, expires_at = str(params[0]), params[1], params[2]
            rt_id = str(uuid.uuid4())
            self.store.refresh_tokens[token_hash] = {
                "id": rt_id,
                "user_id": uid,
                "token_hash": token_hash,
                "revoked": False,
                "replaced_by_id": None,
                "expires_at": expires_at,
            }
            self._one = {"id": rt_id}
            return

        if "FROM public.refresh_tokens rt JOIN public.users u" in q:
            rt = self.store.refresh_tokens.get(params[0])
            if rt:
                u = self.store.users[rt["user_id"]]
                self._one = {**rt, **u, "id": rt["id"], "user_id": rt["user_id"]}
            return

        if "UPDATE public.refresh_tokens SET revoked = TRUE WHERE user_id = %s" in q:
            uid = str(params[0])
            for rt in self.store.refresh_tokens.values():
                if rt["user_id"] == uid:
                    rt["revoked"] = True
            return

        if "UPDATE public.refresh_tokens SET revoked = TRUE, replaced_by_id = %s WHERE id = %s" in q:
            rep_id, rt_id = str(params[0]), str(params[1])
            for rt in self.store.refresh_tokens.values():
                if rt["id"] == rt_id:
                    rt["revoked"] = True
                    rt["replaced_by_id"] = rep_id
            return

        if "UPDATE public.refresh_tokens SET revoked = TRUE WHERE token_hash = %s" in q:
            if params[0] in self.store.refresh_tokens:
                self.store.refresh_tokens[params[0]]["revoked"] = True
            return

        # Activity log
        if "INSERT INTO public.user_activity_log" in q:
            self.store.activity_log.append({"action": params[1], "actor": params[0]})
            return

        # Plans / Products / Coupons
        if "SELECT pl.id AS plan_id" in q and "FROM public.mst_plan pl JOIN public.mst_product pr" in q:
            for pl in self.store.plans.values():
                pr = self.store.products[pl["product_id"]]
                if pl["status"] == "active" and pr["status"] == "active" and pr["is_active"]:
                    self._many.append({
                        "plan_id": pl["id"],
                        "product_id": pl["product_id"],
                        "slug": pr["slug"],
                        "name": pr["name"],
                        "category": pr["category"],
                        "plan_interval": pl["plan_interval"],
                        "duration_days": pl["duration_days"],
                        "amount_paise": pl["amount"],
                        "currency": pl["currency"],
                        "provider_plan_id": pl["provider_plan_id"],
                    })
            return

        if "FROM public.mst_plan pl JOIN public.mst_product pr" in q and "LOWER(pr.name) = LOWER(%s)" in q:
            target = params[0].lower()
            for pl in self.store.plans.values():
                pr = self.store.products[pl["product_id"]]
                if pr["name"].lower() == target and pl["status"] == "active":
                    self._one = dict(pl)
                    return
            return

        if "FROM public.mst_plan pl WHERE pl.id = %s" in q:
            pl = self.store.plans.get(str(params[0]))
            if pl and pl["provider_plan_id"]:
                self._one = dict(pl)
            return

        if "FROM public.mst_coupon" in q:
            code = params[0].lower()
            for c in self.store.coupons.values():
                if c["code"].lower() == code and c["status"] == "active":
                    self._one = dict(c)
                    return
            return

        # Orders / Order Items
        if "INSERT INTO public.orders" in q:
            if len(params) == 6:
                oid, uid, cid, poid, amt, cur = params
                mode = None
            else:
                oid, uid, amt, cur = params
                cid, poid, mode = None, None, "e-mandate"
            self.store.orders[str(oid)] = {
                "id": str(oid),
                "user_id": str(uid),
                "coupon_id": cid,
                "provider_order_id": poid,
                "payment_mode": mode,
                "amount": amt,
                "currency": cur,
                "order_status": "pending",
                "payment_status": "initiated",
            }
            return

        if "INSERT INTO public.order_items" in q:
            self.store.order_items.append({"order_id": str(params[0]), "plan_id": str(params[1]), "amount": params[2]})
            return

        if "FROM public.orders WHERE provider_order_id = %s AND user_id = %s" in q:
            poid, uid = params[0], str(params[1])
            for o in self.store.orders.values():
                if o["provider_order_id"] == poid and o["user_id"] == uid:
                    self._one = dict(o)
                    return
            return

        if "UPDATE public.orders SET payment_status = 'submitted'" in q:
            poid = params[0]
            for o in self.store.orders.values():
                if o["provider_order_id"] == poid:
                    o["payment_status"] = "submitted"
            return

        # Subscriptions
        if "FROM public.subscriptions s JOIN public.mst_plan pl" in q:
            uid = str(params[0])
            for s in self.store.subscriptions.values():
                if s["user_id"] == uid:
                    pl = self.store.plans[s["plan_id"]]
                    pr = self.store.products[s["product_id"]]
                    self._many.append({
                        **s,
                        "plan_interval": pl["plan_interval"],
                        "duration_days": pl["duration_days"],
                        "amount": pl["amount"],
                        "currency": pl["currency"],
                        "product_slug": pr["slug"],
                        "product_name": pr["name"],
                        "product_category": pr["category"],
                    })
            return

        if "SELECT id, subscription_status, starts_at, expires_at FROM public.subscriptions" in q:
            uid, pid = str(params[0]), str(params[1])
            self._many = [
                dict(s)
                for s in self.store.subscriptions.values()
                if s["user_id"] == uid and s["product_id"] == pid and s["subscription_status"] == "active"
            ]
            return

        # PG Business functions & webhooks
        if "SELECT public.apply_payment_success(" in q:
            self.store.function_calls.append(("apply_payment_success", params))
            poid = params[0]
            matching = [o for o in self.store.orders.values() if o["provider_order_id"] == poid]
            if not matching:
                raise NoDataFound(f"ORDER_NOT_FOUND: {poid}")
            order = matching[0]
            order["order_status"] = "placed"
            order["payment_status"] = "credited"
            for item in self.store.order_items:
                if item["order_id"] == order["id"]:
                    pl = self.store.plans[item["plan_id"]]
                    sub_id = str(uuid.uuid4())
                    now = datetime.now(timezone.utc)
                    self.store.subscriptions[sub_id] = {
                        "id": sub_id,
                        "user_id": order["user_id"],
                        "product_id": pl["product_id"],
                        "plan_id": pl["id"],
                        "order_id": order["id"],
                        "subscription_status": "active",
                        "starts_at": now - timedelta(minutes=1),
                        "expires_at": now + timedelta(days=pl["duration_days"]),
                        "auto_renew": False,
                        "provider_subscription_id": None,
                        "auth_status": None,
                        "next_charge_at": None,
                        "created_date": now,
                        "status": "active",
                    }
            return

        if "SELECT public.apply_payment_failure(" in q:
            self.store.function_calls.append(("apply_payment_failure", params))
            return

        if "SELECT public.apply_subscription_charged(" in q:
            self.store.function_calls.append(("apply_subscription_charged", params))
            return

        if "SELECT public.apply_subscription_status(" in q:
            self.store.function_calls.append(("apply_subscription_status", params))
            return

        if "SELECT public.register_webhook_event(" in q:
            eid = params[0]
            is_new = eid not in self.store.webhook_events
            if is_new:
                self.store.webhook_events[eid] = {"event_id": eid, "processed_at": None}
            self._one = {"registered": is_new}
            return

        raise AssertionError(f"Unhandled SQL in test double: {q}")


class FakeConnection:
    """Minimal psycopg-compatible connection double for sandbox testing."""

    def __init__(self, store: InMemoryStore) -> None:
        self.store = store
        self.closed = False
        self.commits = 0
        self.rollbacks = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.store)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True

    @contextmanager
    def transaction(self):
        yield


def make_request(cookies: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> Request:
    raw_headers = []
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie_str.encode("latin-1")))
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": raw_headers,
        "client": ("127.0.0.1", 50000),
    }
    return Request(scope)


class TestBeEvolvePostgresBackend(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryStore()
        self.conn = FakeConnection(self.store)
        auth_routes._login_attempts.clear()

    def test_01_openapi_and_health_db(self) -> None:
        schema = main.app.openapi()
        paths = set(schema["paths"].keys())
        expected = {
            "/",
            "/api/health",
            "/api/health/db",
            "/api/auth/register",
            "/api/auth/email-otp/send",
            "/api/auth/email-otp/verify",
            "/api/auth/login",
            "/api/auth/me",
            "/api/auth/refresh",
            "/api/auth/logout",
            "/api/auth/forgot-password",
            "/api/auth/oauth/exchange",
            "/api/auth/update-password",
            "/api/auth/oauth/google",
            "/api/auth/oauth/google/callback",
            "/api/auth/google",
            "/api/auth/profile",
            "/api/payments/create-order",
            "/api/payments/verify",
            "/api/subscriptions/create",
            "/api/subscriptions/me",
            "/api/subscriptions/access/{product_id}",
            "/api/webhooks/razorpay",
        }
        self.assertTrue(expected.issubset(paths))
        health = main.health_db(self.conn)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["tables_found"], 14)

    def test_02_register_otp_login_cookies_refresh_and_logout(self) -> None:
        # Mismatched confirm_password -> 422
        with self.assertRaises(HTTPException) as ctx:
            auth_routes.register_user(
                auth_routes.RegisterRequest(
                    name="Tanay",
                    email="tanay@example.com",
                    mobile="9876543210",
                    password="Password@1",
                    confirm_password="Password@2",
                ),
                self.conn,
            )
        self.assertEqual(ctx.exception.status_code, 422)

        # Valid register -> 201
        reg = auth_routes.register_user(
            auth_routes.RegisterRequest(
                name="Tanay",
                email="tanay@example.com",
                mobile="9876543210",
                password="Password@1",
                confirm_password="Password@1",
            ),
            self.conn,
        )
        self.assertTrue(reg["success"])
        user_id = reg["user_id"]
        saved = self.store.users[user_id]
        self.assertNotEqual(saved["password_hash"], "Password@1")
        self.assertTrue(security.verify_password("Password@1", saved["password_hash"]))

        # Duplicate mobile -> 409
        with self.assertRaises(HTTPException) as dup:
            auth_routes.register_user(
                auth_routes.RegisterRequest(
                    name="Other",
                    email="other@example.com",
                    mobile="+919876543210",
                    password="Password@1",
                    confirm_password="Password@1",
                ),
                self.conn,
            )
        self.assertEqual(dup.exception.status_code, 409)

        # OTP send & verify
        sent_otps = []
        with patch.object(security, "generate_email_otp", return_value="AB34XY"), patch.object(
            auth_routes, "generate_email_otp", return_value="AB34XY"
        ), patch.object(auth_routes, "_send_smtp_email", side_effect=lambda to, s, b: sent_otps.append((to, b))):
            otp_resp = auth_routes.send_email_otp(
                auth_routes.SendEmailOtpRequest(email="tanay@example.com", user_id=user_id),
                self.conn,
            )
        self.assertTrue(otp_resp["success"])
        self.assertEqual(len(sent_otps), 1)
        otp_res = Response()
        verified = auth_routes.verify_email_otp(
            auth_routes.VerifyEmailOtpRequest(email="tanay@example.com", user_id=user_id, code="AB34XY"),
            otp_res,
            self.conn,
        )
        self.assertTrue(verified["success"])
        self.assertTrue(verified["authenticated"])
        self.assertTrue(self.store.users[user_id]["email_verified"])
        otp_cookies = [v.decode("latin-1") for k, v in otp_res.raw_headers if k.lower() == b"set-cookie"]
        self.assertEqual(len(otp_cookies), 2)
        self.assertTrue(any("beevolve_access=" in c and "HttpOnly" in c for c in otp_cookies))
        self.assertTrue(any("beevolve_refresh=" in c and "HttpOnly" in c for c in otp_cookies))
        otp_access = otp_cookies[0].split("=", 1)[1].split(";", 1)[0]
        otp_me = auth_routes.current_user(make_request(cookies={"beevolve_access": otp_access}), self.conn)
        self.assertTrue(otp_me["authenticated"])

        # Login sets HttpOnly cookies
        login_res = Response()
        login_body = auth_routes.login_user(
            auth_routes.LoginRequest(email="tanay@example.com", password="Password@1"),
            make_request(),
            login_res,
            self.conn,
        )
        self.assertTrue(login_body["authenticated"])
        set_cookies = [v.decode("latin-1") for k, v in login_res.raw_headers if k.lower() == b"set-cookie"]
        self.assertEqual(len(set_cookies), 2)
        self.assertTrue(any("beevolve_access=" in c and "HttpOnly" in c for c in set_cookies))
        self.assertTrue(any("beevolve_refresh=" in c and "HttpOnly" in c for c in set_cookies))

        access_val = set_cookies[0].split("=", 1)[1].split(";", 1)[0]
        refresh_val = set_cookies[1].split("=", 1)[1].split(";", 1)[0]

        # /me works with HttpOnly cookie AND Bearer header
        me = auth_routes.current_user(make_request(cookies={"beevolve_access": access_val}), self.conn)
        self.assertTrue(me["authenticated"])
        self.assertEqual(me["user"]["user_metadata"]["full_name"], "Tanay")

        uid_dep = auth_routes.get_current_user(
            make_request(headers={"Authorization": f"Bearer {access_val}"}),
            self.conn,
        )
        self.assertEqual(uid_dep["id"], user_id)

        # Refresh rotates token and revokes old one
        ref_res = Response()
        ref_body = auth_routes.refresh_session(
            make_request(cookies={"beevolve_refresh": refresh_val}),
            ref_res,
            None,
            self.conn,
        )
        self.assertTrue(ref_body["authenticated"])
        ref_cookies = [v.decode("latin-1") for k, v in ref_res.raw_headers if k.lower() == b"set-cookie"]
        new_refresh = ref_cookies[1].split("=", 1)[1].split(";", 1)[0]
        self.assertNotEqual(new_refresh, refresh_val)

        # Replaying old refresh token detects reuse & revokes all
        with self.assertRaises(HTTPException) as reuse_err:
            auth_routes.refresh_session(
                make_request(cookies={"beevolve_refresh": refresh_val}),
                Response(),
                None,
                self.conn,
            )
        self.assertEqual(reuse_err.exception.status_code, 401)
        self.assertTrue(all(rt["revoked"] for rt in self.store.refresh_tokens.values()))

    def test_03_forgot_and_update_password(self) -> None:
        reg = auth_routes.register_user(
            auth_routes.RegisterRequest(
                name="Reset User",
                email="reset@example.com",
                mobile="9876543211",
                password="Password@1",
                confirm_password="Password@1",
            ),
            self.conn,
        )
        uid = reg["user_id"]
        mails = []
        with patch.object(auth_routes, "_send_smtp_email", side_effect=lambda to, s, b: mails.append(b)):
            auth_routes.forgot_password(auth_routes.ForgotPasswordRequest(email="reset@example.com"), self.conn)
        self.assertEqual(len(mails), 1)
        reset_token = mails[0].split("?token=")[1].splitlines()[0].strip()

        # Exchanging reset token MUST NOT issue beevolve_access, only beevolve_reset
        ex_res = Response()
        ex_body = auth_routes.oauth_exchange(
            auth_routes.OAuthExchangeRequest(access_token=reset_token),
            ex_res,
        )
        self.assertFalse(ex_body["authenticated"])
        ex_cookies = [v.decode("latin-1") for k, v in ex_res.raw_headers if k.lower() == b"set-cookie"]
        self.assertTrue(any("beevolve_reset=" in c for c in ex_cookies))
        self.assertFalse(any("beevolve_access=" in c for c in ex_cookies))

        up_body = auth_routes.update_password(
            auth_routes.UpdatePasswordRequest(password="NewPass@2"),
            make_request(cookies={"beevolve_reset": reset_token}),
            Response(),
            self.conn,
        )
        self.assertTrue(up_body["success"])
        self.assertTrue(security.verify_password("NewPass@2", self.store.users[uid]["password_hash"]))

    def test_04_google_oauth_and_payments_and_webhooks(self) -> None:
        # Google consent URL + callback cookie issue
        oauth_info = auth_routes.google_oauth()
        self.assertIn("accounts.google.com", oauth_info["url"])
        state = oauth_info["url"].split("state=")[1].split("&")[0]

        class DummyResp:
            status_code = 200
            def json(self):
                return {"id_token": "fake.google.id.token"}

        with patch.object(auth_routes.httpx, "post", return_value=DummyResp()), patch.object(
            auth_routes,
            "_verify_google_id_token_claims",
            return_value={
                "sub": "google-sub-123",
                "email": "guser@example.com",
                "name": "Google User",
                "email_verified": True,
            },
        ):
            redir = auth_routes.google_oauth_callback(code="auth-code", state=state, error=None, conn=self.conn)
        self.assertEqual(redir.status_code, 302)
        self.assertTrue(redir.headers["location"].endswith("/dashboard.html"))
        self.assertIn(("google", "google-sub-123"), self.store.oauth_accounts)
        uid = self.store.oauth_accounts[("google", "google-sub-123")]["user_id"]

        # Plans endpoint reflects live DB amount (100 paise -> Rs. 1) and DB changes immediately
        catalog = sub_routes.list_active_plans(conn=self.conn)
        self.assertEqual(catalog["plans"][0]["amount_paise"], 100)
        self.assertEqual(catalog["plans"][0]["amount_rupees"], 1)

        # Create Razorpay order with SAVE20 coupon (100 -> 80)
        with patch.object(payment_routes, "client") as mock_rzp:
            mock_rzp.order.create.return_value = {"id": "order_rzp_1", "amount": 80, "currency": "INR"}
            order_resp = payment_routes.create_order(
                payment_routes.OrderRequest(service="Career Toolkit", coupon_code="SAVE20"),
                user_id=uid,
                conn=self.conn,
            )
            self.assertEqual(order_resp["amount"], 80)

            mock_rzp.payment.fetch.return_value = {
                "order_id": "order_rzp_1",
                "amount": 80,
                "status": "captured",
                "method": "upi",
            }
            verify_resp = payment_routes.verify_payment(
                payment_routes.PaymentVerification(
                    razorpay_order_id="order_rzp_1",
                    razorpay_payment_id="pay_rzp_1",
                    razorpay_signature="valid_sig",
                ),
                user_id=uid,
                conn=self.conn,
            )
        self.assertTrue(verify_resp["success"])

        # Subscriptions /me renders product name for dashboard.html
        subs = sub_routes.get_my_subscriptions(user_id=uid, conn=self.conn)
        self.assertEqual(len(subs["subscriptions"]), 1)
        self.assertEqual(subs["subscriptions"][0]["mst_plan"]["mst_product"]["name"], "Career Toolkit")

        prod_id = subs["subscriptions"][0]["product_id"]
        access = sub_routes.check_product_access(uuid.UUID(prod_id), user_id=uid, conn=self.conn)
        self.assertTrue(access["has_access"])

        # Updating price in DB immediately reflects in /api/subscriptions/plans
        self.store.plans["61af1c9e-ba0f-4a83-ac8d-e95773a13b04"]["amount"] = 250
        updated_catalog = sub_routes.list_active_plans(conn=self.conn)
        self.assertEqual(updated_catalog["plans"][0]["amount_rupees"], 2.5)

        # Webhook dispatch handles autopay NoDataFound & subscription.cancelled cleanly
        webhook_routes.dispatch_event(
            self.conn,
            "payment.captured",
            {"payload": {"payment": {"entity": {"order_id": "order_autopay_missing", "id": "pay_auto_1", "amount": 49900}}}},
        )
        webhook_routes.dispatch_event(
            self.conn,
            "subscription.cancelled",
            {"payload": {"subscription": {"entity": {"id": "sub_rzp_1", "status": "cancelled"}}}},
        )
        fn_names = [call[0] for call in self.store.function_calls]
        self.assertIn("apply_subscription_status", fn_names)

    def test_05_profile_subscription_create_and_lockout(self) -> None:
        reg = auth_routes.register_user(
            auth_routes.RegisterRequest(
                name="Profile User",
                email="profile@example.com",
                mobile="9876543212",
                password="Password@1",
                confirm_password="Password@1",
            ),
            self.conn,
        )
        uid = reg["user_id"]

        # GET and PUT /profile
        prof = auth_routes.profile(user_id=uid, conn=self.conn)
        self.assertEqual(prof["profile"]["full_name"], "Profile User")

        updated = auth_routes.update_profile(
            auth_routes.UpdateProfileRequest(
                full_name="Updated User",
                mobile="9876543213",
                email="profile@example.com",
            ),
            user_id=uid,
            conn=self.conn,
        )
        self.assertEqual(updated["profile"]["mobile"], "+919876543213")

        # Subscription creation resolves by service fallback when plan_id UUID differs
        with patch.object(sub_routes, "client") as mock_rzp:
            mock_rzp.subscription.create.return_value = {
                "id": "sub_created_1",
                "short_url": "https://rzp.io/i/sub_created_1",
                "status": "created",
            }
            created_sub = sub_routes.create_subscription(
                sub_routes.SubscriptionRequest(
                    plan_id="00000000-0000-0000-0000-000000000000",
                    service="Career Toolkit",
                ),
                user_id=uid,
                conn=self.conn,
            )
        self.assertTrue(created_sub["success"])
        self.assertEqual(created_sub["subscription_id"], "sub_created_1")

        # 5 wrong passwords lock the account (429)
        for attempt in range(5):
            with self.assertRaises(HTTPException) as ctx:
                auth_routes.login_user(
                    auth_routes.LoginRequest(email="profile@example.com", password="Wrong@123"),
                    make_request(),
                    Response(),
                    self.conn,
                )
            expected_status = 429 if attempt == 4 else 401
            self.assertEqual(ctx.exception.status_code, expected_status)


if __name__ == "__main__":
    unittest.main()
