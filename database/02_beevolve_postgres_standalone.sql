-- ============================================================================
-- BeEvolve Project | Complete Standalone PostgreSQL 18 Schema (All 14 Tables)
-- Replaces Supabase Auth + PostgREST + RLS dependencies with direct PostgreSQL.
-- Safe to re-run (IF NOT EXISTS / CREATE OR REPLACE).
-- ============================================================================

-- ============================================================================
-- 1. EXTENSIONS + TYPES
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS citext;

DO $$
BEGIN
  CREATE TYPE public.user_role AS ENUM ('user', 'admin');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- 2. SHARED FUNCTION: audit columns (created_by / updated_by / updated_date)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.set_audit_fields()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  ELSE
    NEW.created_date := OLD.created_date;
    NEW.created_by   := OLD.created_by;
    NEW.updated_date := NOW();
    RETURN NEW;
  END IF;
END;
$$;

-- ============================================================================
-- 3. TABLES (dependency order)
--    users -> mst_coupon -> mst_product -> mst_plan -> orders -> order_items
--    -> subscriptions -> subscription_payments -> notifications
--    -> otp_verifications -> refresh_tokens -> user_activity_log
--    -> oauth_accounts -> webhook_events
-- ============================================================================

-- 3.1 users
CREATE TABLE IF NOT EXISTS public.users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email          CITEXT NOT NULL UNIQUE,
  full_name      TEXT NOT NULL DEFAULT '',
  mobile         TEXT UNIQUE,
  password_hash  TEXT,
  role           public.user_role NOT NULL DEFAULT 'user',
  account_status TEXT NOT NULL DEFAULT 'active'
                 CHECK (account_status IN ('active','suspended','deleted')),
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_at     TIMESTAMPTZ,
  created_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by     UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by     UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS password_hash  TEXT;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS mfa_enabled    BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS deleted_at     TIMESTAMPTZ;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS created_by     UUID REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_by     UUID REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'));

-- 3.2 mst_coupon
CREATE TABLE IF NOT EXISTS public.mst_coupon (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code             TEXT NOT NULL UNIQUE,
  discount_type    TEXT NOT NULL CHECK (discount_type IN ('percent','flat')),
  discount_value   INTEGER NOT NULL CHECK (discount_value > 0),
  max_redemptions  INTEGER CHECK (max_redemptions IS NULL OR max_redemptions >= 0),
  times_redeemed   INTEGER NOT NULL DEFAULT 0 CHECK (times_redeemed >= 0),
  start_date       DATE,
  expiry_date      DATE,
  created_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  CONSTRAINT mst_coupon_percent_max CHECK (discount_type <> 'percent' OR discount_value <= 100),
  CONSTRAINT mst_coupon_dates CHECK (start_date IS NULL OR expiry_date IS NULL OR expiry_date >= start_date)
);

-- 3.3 mst_product
CREATE TABLE IF NOT EXISTS public.mst_product (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug          TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  category      TEXT,
  ai_provider   TEXT,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  start_date    DATE,
  end_date      DATE,
  created_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  CONSTRAINT mst_product_dates CHECK (start_date IS NULL OR end_date IS NULL OR end_date >= start_date)
);

-- 3.4 mst_plan
CREATE TABLE IF NOT EXISTS public.mst_plan (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id       UUID NOT NULL REFERENCES public.mst_product(id) ON DELETE RESTRICT,
  plan_interval    TEXT NOT NULL CHECK (plan_interval IN ('monthly','quarterly','annual','enterprise')),
  duration_days    INTEGER NOT NULL CHECK (duration_days > 0),
  amount           INTEGER NOT NULL CHECK (amount >= 0),
  currency         TEXT NOT NULL DEFAULT 'INR' CHECK (char_length(currency) = 3),
  usage_limit      INTEGER CHECK (usage_limit IS NULL OR usage_limit >= 0),
  provider_plan_id TEXT UNIQUE,
  start_date       DATE,
  end_date         DATE,
  expiry_date      DATE,
  created_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  CONSTRAINT mst_plan_dates CHECK (start_date IS NULL OR end_date IS NULL OR end_date >= start_date)
);

-- 3.5 orders
CREATE TABLE IF NOT EXISTS public.orders (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  coupon_id           UUID REFERENCES public.mst_coupon(id) ON DELETE RESTRICT,
  order_status        TEXT NOT NULL DEFAULT 'pending'
                      CHECK (order_status IN ('pending','placed','failed')),
  payment_status      TEXT NOT NULL DEFAULT 'initiated'
                      CHECK (payment_status IN ('initiated','submitted','credited','debited')),
  payment_mode        TEXT CHECK (payment_mode IN ('card','e-mandate','upi','netbanking')),
  payment_provider    TEXT NOT NULL DEFAULT 'razorpay' CHECK (payment_provider IN ('razorpay','stripe')),
  provider_order_id   TEXT UNIQUE,
  provider_payment_id TEXT,
  zoho_invoice_id     TEXT,
  signature_verified  BOOLEAN NOT NULL DEFAULT FALSE,
  amount              INTEGER NOT NULL CHECK (amount >= 0),
  currency            TEXT NOT NULL DEFAULT 'INR' CHECK (char_length(currency) = 3),
  created_date        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by          UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by          UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

-- 3.6 order_items
CREATE TABLE IF NOT EXISTS public.order_items (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id      UUID NOT NULL REFERENCES public.orders(id) ON DELETE CASCADE,
  plan_id       UUID NOT NULL REFERENCES public.mst_plan(id) ON DELETE RESTRICT,
  amount        INTEGER NOT NULL CHECK (amount >= 0),
  created_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  CONSTRAINT order_items_order_plan_uk UNIQUE (order_id, plan_id)
);

-- 3.7 subscriptions
CREATE TABLE IF NOT EXISTS public.subscriptions (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                  UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  product_id               UUID NOT NULL REFERENCES public.mst_product(id) ON DELETE RESTRICT,
  plan_id                  UUID NOT NULL REFERENCES public.mst_plan(id) ON DELETE RESTRICT,
  order_id                 UUID NOT NULL REFERENCES public.orders(id) ON DELETE RESTRICT,
  subscription_status      TEXT NOT NULL DEFAULT 'active'
                           CHECK (subscription_status IN ('active','expired','cancelled','refunded')),
  starts_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at               TIMESTAMPTZ,
  auto_renew               BOOLEAN NOT NULL DEFAULT FALSE,
  provider_subscription_id TEXT UNIQUE,
  payment_method           TEXT,
  auth_status              TEXT,
  next_charge_at           TIMESTAMPTZ,
  created_date             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by               UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by               UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status                   TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  CONSTRAINT subscriptions_order_plan_uk UNIQUE (order_id, plan_id),
  CONSTRAINT subscriptions_dates CHECK (expires_at IS NULL OR expires_at > starts_at)
);

-- 3.8 subscription_payments
CREATE TABLE IF NOT EXISTS public.subscription_payments (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id     UUID NOT NULL REFERENCES public.subscriptions(id) ON DELETE RESTRICT,
  provider_payment_id TEXT NOT NULL UNIQUE,
  amount              INTEGER NOT NULL CHECK (amount >= 0),
  payment_status      TEXT NOT NULL DEFAULT 'captured'
                      CHECK (payment_status IN ('captured','failed','refunded')),
  payment_date        TIMESTAMPTZ,
  created_date        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by          UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by          UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

-- 3.9 notifications
CREATE TABLE IF NOT EXISTS public.notifications (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  channel          TEXT NOT NULL,
  sent_at          TIMESTAMPTZ,
  delivery_status  TEXT NOT NULL DEFAULT 'pending',
  created_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

-- 3.10 otp_verifications
CREATE TABLE IF NOT EXISTS public.otp_verifications (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  otp_hash      TEXT NOT NULL,
  purpose       TEXT NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  expires_at    TIMESTAMPTZ NOT NULL,
  created_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

-- 3.11 refresh_tokens
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_hash       TEXT NOT NULL UNIQUE,
  revoked          BOOLEAN NOT NULL DEFAULT FALSE,
  replaced_by_id   UUID REFERENCES public.refresh_tokens(id) ON DELETE SET NULL,
  expires_at       TIMESTAMPTZ NOT NULL,
  created_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS created_by   UUID REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS updated_date TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS updated_by   UUID REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.refresh_tokens ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'));

-- 3.12 user_activity_log
CREATE TABLE IF NOT EXISTS public.user_activity_log (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id  UUID REFERENCES public.users(id) ON DELETE SET NULL,
  action         TEXT NOT NULL,
  entity_type    TEXT,
  entity_id      UUID,
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by     UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by     UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'))
);

-- 3.13 oauth_accounts
CREATE TABLE IF NOT EXISTS public.oauth_accounts (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  provider          TEXT NOT NULL,
  provider_user_id  TEXT NOT NULL,
  created_date      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by        UUID REFERENCES public.users(id) ON DELETE SET NULL,
  updated_date      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by        UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  CONSTRAINT oauth_accounts_provider_uk UNIQUE (provider, provider_user_id)
);

ALTER TABLE public.oauth_accounts ADD COLUMN IF NOT EXISTS created_by   UUID REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.oauth_accounts ADD COLUMN IF NOT EXISTS updated_date TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE public.oauth_accounts ADD COLUMN IF NOT EXISTS updated_by   UUID REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE public.oauth_accounts ADD COLUMN IF NOT EXISTS status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive'));

-- 3.14 webhook_events
CREATE TABLE IF NOT EXISTS public.webhook_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      TEXT NOT NULL UNIQUE,
  event_type    TEXT NOT NULL,
  payload       JSONB NOT NULL,
  received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at  TIMESTAMPTZ,
  error         TEXT
);

-- ============================================================================
-- 4. INDEXES
-- ============================================================================
CREATE UNIQUE INDEX IF NOT EXISTS orders_provider_payment_uk
  ON public.orders (provider_payment_id) WHERE provider_payment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS orders_user_id_idx            ON public.orders (user_id);
CREATE INDEX IF NOT EXISTS orders_coupon_id_idx          ON public.orders (coupon_id);
CREATE INDEX IF NOT EXISTS order_items_order_id_idx      ON public.order_items (order_id);
CREATE INDEX IF NOT EXISTS order_items_plan_id_idx       ON public.order_items (plan_id);
CREATE INDEX IF NOT EXISTS mst_plan_product_id_idx       ON public.mst_plan (product_id);
CREATE INDEX IF NOT EXISTS subscriptions_user_id_idx     ON public.subscriptions (user_id);
CREATE INDEX IF NOT EXISTS subscriptions_product_id_idx  ON public.subscriptions (product_id);
CREATE INDEX IF NOT EXISTS subscriptions_plan_id_idx     ON public.subscriptions (plan_id);
CREATE INDEX IF NOT EXISTS subscriptions_expires_at_idx  ON public.subscriptions (expires_at);
CREATE INDEX IF NOT EXISTS sub_payments_subscription_idx ON public.subscription_payments (subscription_id);
CREATE INDEX IF NOT EXISTS notifications_user_id_idx     ON public.notifications (user_id);
CREATE INDEX IF NOT EXISTS otp_user_purpose_idx          ON public.otp_verifications (user_id, purpose, created_date DESC);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx    ON public.refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS activity_actor_idx            ON public.user_activity_log (actor_user_id);
CREATE INDEX IF NOT EXISTS activity_entity_idx           ON public.user_activity_log (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS oauth_accounts_user_id_idx    ON public.oauth_accounts (user_id);

-- ============================================================================
-- 5. AUDIT TRIGGERS
-- ============================================================================
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','mst_coupon','mst_product','mst_plan','orders','order_items',
    'subscriptions','subscription_payments','notifications','otp_verifications',
    'refresh_tokens','user_activity_log','oauth_accounts'
  ]
  LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%1$s_audit ON public.%1$I', t);
    EXECUTE format(
      'CREATE TRIGGER trg_%1$s_audit BEFORE INSERT OR UPDATE ON public.%1$I
         FOR EACH ROW EXECUTE FUNCTION public.set_audit_fields()', t);
  END LOOP;
END $$;

-- ============================================================================
-- 6. BUSINESS FUNCTIONS (Razorpay / Order / Webhook helpers)
-- ============================================================================
CREATE OR REPLACE FUNCTION public.apply_payment_success(
  p_provider_order_id   TEXT,
  p_provider_payment_id TEXT,
  p_payment_mode        TEXT    DEFAULT NULL,
  p_amount              INTEGER DEFAULT NULL,
  p_signature_verified  BOOLEAN DEFAULT FALSE
)
RETURNS UUID
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  v_order public.orders%ROWTYPE;
  v_first BOOLEAN;
  v_mode  TEXT;
BEGIN
  SELECT * INTO v_order FROM public.orders
   WHERE provider_order_id = p_provider_order_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ORDER_NOT_FOUND: %', p_provider_order_id USING ERRCODE = 'P0002';
  END IF;

  IF p_amount IS NOT NULL AND p_amount <> v_order.amount THEN
    RAISE EXCEPTION 'AMOUNT_MISMATCH: order % expects %, got %', v_order.id, v_order.amount, p_amount
      USING ERRCODE = 'P0003';
  END IF;

  v_mode := CASE LOWER(COALESCE(p_payment_mode, ''))
              WHEN 'emandate'   THEN 'e-mandate'
              WHEN 'e-mandate'  THEN 'e-mandate'
              WHEN 'card'       THEN 'card'
              WHEN 'upi'        THEN 'upi'
              WHEN 'netbanking' THEN 'netbanking'
              ELSE NULL END;

  v_first := (v_order.order_status <> 'placed');

  UPDATE public.orders
     SET order_status        = 'placed',
         payment_status      = 'credited',
         provider_payment_id = COALESCE(provider_payment_id, p_provider_payment_id),
         payment_mode        = COALESCE(v_mode, payment_mode),
         signature_verified  = signature_verified OR COALESCE(p_signature_verified, FALSE)
   WHERE id = v_order.id;

  IF v_first THEN
    INSERT INTO public.subscriptions
      (user_id, product_id, plan_id, order_id, subscription_status, starts_at, expires_at, auto_renew)
    SELECT v_order.user_id, p.product_id, oi.plan_id, v_order.id, 'active',
           NOW(), NOW() + make_interval(days => p.duration_days), FALSE
      FROM public.order_items oi
      JOIN public.mst_plan p ON p.id = oi.plan_id
     WHERE oi.order_id = v_order.id
    ON CONFLICT (order_id, plan_id) DO NOTHING;

    IF v_order.coupon_id IS NOT NULL THEN
      UPDATE public.mst_coupon SET times_redeemed = times_redeemed + 1 WHERE id = v_order.coupon_id;
    END IF;
  END IF;

  RETURN v_order.id;
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_payment_failure(
  p_provider_order_id TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE v_id UUID;
BEGIN
  UPDATE public.orders
     SET order_status = 'failed'
   WHERE provider_order_id = p_provider_order_id
     AND order_status <> 'placed'
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_subscription_charged(
  p_order_id                 UUID,
  p_provider_subscription_id TEXT,
  p_provider_payment_id      TEXT,
  p_provider_order_id        TEXT,
  p_amount                   INTEGER,
  p_paid_at                  TIMESTAMPTZ DEFAULT NULL,
  p_current_end              TIMESTAMPTZ DEFAULT NULL,
  p_charge_at                TIMESTAMPTZ DEFAULT NULL,
  p_payment_method           TEXT        DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  v_order public.orders%ROWTYPE;
  v_plan  RECORD;
  v_sub   UUID;
  v_first BOOLEAN;
  v_paid  TIMESTAMPTZ := COALESCE(p_paid_at, NOW());
BEGIN
  SELECT * INTO v_order FROM public.orders WHERE id = p_order_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ORDER_NOT_FOUND: %', p_order_id USING ERRCODE = 'P0002';
  END IF;

  SELECT oi.plan_id, p.product_id, p.duration_days
    INTO v_plan
    FROM public.order_items oi
    JOIN public.mst_plan p ON p.id = oi.plan_id
   WHERE oi.order_id = v_order.id
   ORDER BY oi.created_date
   LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ORDER_HAS_NO_ITEMS: %', v_order.id USING ERRCODE = 'P0002';
  END IF;

  v_first := (v_order.order_status <> 'placed');
  IF v_first AND p_amount <> v_order.amount THEN
    RAISE EXCEPTION 'AMOUNT_MISMATCH: order % expects %, got %', v_order.id, v_order.amount, p_amount
      USING ERRCODE = 'P0003';
  END IF;

  INSERT INTO public.subscriptions
    (user_id, product_id, plan_id, order_id, subscription_status, starts_at, expires_at,
     auto_renew, provider_subscription_id, payment_method, auth_status, next_charge_at)
  VALUES
    (v_order.user_id, v_plan.product_id, v_plan.plan_id, v_order.id, 'active', v_paid,
     COALESCE(p_current_end, v_paid + make_interval(days => v_plan.duration_days)),
     TRUE, p_provider_subscription_id, p_payment_method, 'active', p_charge_at)
  ON CONFLICT (provider_subscription_id) DO UPDATE
    SET subscription_status = 'active',
        expires_at          = GREATEST(subscriptions.expires_at, EXCLUDED.expires_at),
        next_charge_at      = EXCLUDED.next_charge_at,
        auth_status         = 'active',
        auto_renew          = TRUE
  RETURNING id INTO v_sub;

  INSERT INTO public.subscription_payments
    (subscription_id, provider_payment_id, amount, payment_status, payment_date)
  VALUES (v_sub, p_provider_payment_id, p_amount, 'captured', v_paid)
  ON CONFLICT (provider_payment_id) DO NOTHING;

  UPDATE public.orders
     SET order_status        = 'placed',
         payment_status      = 'credited',
         payment_mode        = COALESCE(payment_mode, 'e-mandate'),
         provider_order_id   = COALESCE(provider_order_id, p_provider_order_id),
         provider_payment_id = COALESCE(provider_payment_id, p_provider_payment_id)
   WHERE id = v_order.id;

  IF v_first AND v_order.coupon_id IS NOT NULL THEN
    UPDATE public.mst_coupon SET times_redeemed = times_redeemed + 1 WHERE id = v_order.coupon_id;
  END IF;

  RETURN v_sub;
END;
$$;

CREATE OR REPLACE FUNCTION public.apply_subscription_status(
  p_provider_subscription_id TEXT,
  p_provider_status          TEXT,
  p_charge_at                TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE v_id UUID;
BEGIN
  UPDATE public.subscriptions s
     SET auth_status         = p_provider_status,
         subscription_status = CASE p_provider_status
                                 WHEN 'cancelled' THEN 'cancelled'
                                 WHEN 'completed' THEN 'expired'
                                 WHEN 'halted'    THEN 'expired'
                                 ELSE s.subscription_status END,
         auto_renew          = (p_provider_status IN ('active','authenticated')),
         next_charge_at      = COALESCE(p_charge_at, s.next_charge_at)
   WHERE s.provider_subscription_id = p_provider_subscription_id
     AND NOT (s.subscription_status IN ('cancelled','refunded')
              AND p_provider_status IN ('created','authenticated','active','pending'))
  RETURNING s.id INTO v_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.register_webhook_event(
  p_event_id   TEXT,
  p_event_type TEXT,
  p_payload    JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE v_id UUID;
BEGIN
  INSERT INTO public.webhook_events (event_id, event_type, payload)
  VALUES (p_event_id, p_event_type, p_payload)
  ON CONFLICT (event_id) DO NOTHING
  RETURNING id INTO v_id;
  RETURN v_id IS NOT NULL;
END;
$$;

-- ============================================================================
-- 7. SEED DATA (Products & Plans aligned with Frontend/subscriptions.html)
-- ============================================================================
INSERT INTO public.mst_product (slug, name, category) VALUES
  ('career-toolkit',    'Career Toolkit',        'career'),
  ('portfolio-review',  'Portfolio Review',      'career'),
  ('career-roadmap',    'Career Roadmap',        'career'),
  ('beevolve-premium',  'Beevolve Premium Plan', 'subscription')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO public.mst_plan (id, product_id, plan_interval, duration_days, amount, currency)
SELECT v.plan_uuid, p.id, v.plan_interval, v.duration_days, v.amount, 'INR'
  FROM (VALUES
    ('61af1c9e-ba0f-4a83-ac8d-e95773a13b04'::uuid, 'career-toolkit',   'annual',  365, 100),
    ('c27ffd2c-eeb8-40a6-86f8-38eea10b7446'::uuid, 'portfolio-review', 'annual',  365, 100),
    ('8a4d8288-d4fd-43d9-8f50-af1efc13c98b'::uuid, 'career-roadmap',   'annual',  365, 100),
    (gen_random_uuid(),                            'beevolve-premium', 'monthly',  30, 100)
  ) AS v(plan_uuid, slug, plan_interval, duration_days, amount)
  JOIN public.mst_product p ON p.slug = v.slug
 WHERE NOT EXISTS (SELECT 1 FROM public.mst_plan x WHERE x.product_id = p.id);
