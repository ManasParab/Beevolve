-- ============================================================================
-- BeEvolve  |  01_beevolve_create.sql
-- Run in: Supabase Dashboard -> SQL Editor (as one script, top to bottom).
-- Safe to re-run (IF NOT EXISTS / CREATE OR REPLACE / DROP POLICY IF EXISTS).
-- Source of truth: new_ER.png. Deviations from the ER are marked "ER-DEVIATION".
-- ============================================================================

-- ============================================================================
-- 1. EXTENSIONS + TYPES
-- ============================================================================
create extension if not exists citext with schema extensions;

do $$
begin
  create type public.user_role as enum ('user', 'admin');
exception when duplicate_object then null;
end $$;

-- ============================================================================
-- 2. SHARED FUNCTION: audit columns (created_by / updated_by / updated_date)
--    auth.uid() is NULL for the backend secret key, so the backend may set
--    created_by / updated_by explicitly; this function never overwrites them.
-- ============================================================================
create or replace function public.set_audit_fields()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'INSERT' then
    new.created_by := coalesce(new.created_by, auth.uid());
  else
    new.created_date := old.created_date;
    new.created_by   := old.created_by;
    new.updated_date := now();
    new.updated_by   := coalesce(auth.uid(), new.updated_by);
  end if;
  return new;
end;
$$;

-- ============================================================================
-- 3. TABLES  (dependency order)
--    users -> mst_coupon -> mst_product -> mst_plan -> orders -> order_items
--    -> subscriptions -> subscription_payments -> notifications
--    -> otp_verifications -> refresh_tokens -> user_activity_log
--    -> oauth_accounts -> webhook_events
-- ============================================================================

-- 3.1 users  (id = auth.users.id; Supabase Auth owns passwords/sessions)
create table if not exists public.users (
  id             uuid primary key references auth.users(id) on delete cascade,
  email          extensions.citext not null unique,
  full_name      text not null default '',              -- ER-DEVIATION: needed by dashboard profile (was profiles.full_name)
  mobile         text,                                  -- ER-DEVIATION: needed by dashboard profile (was profiles.mobile)
  password_hash  text,                                  -- always NULL: Supabase Auth owns passwords. Never write.
  role           public.user_role not null default 'user',
  account_status text not null default 'active'
                 check (account_status in ('active','suspended','deleted')),
  email_verified boolean not null default false,
  mfa_enabled    boolean not null default false,
  deleted_at     timestamptz,
  created_date   timestamptz not null default now(),
  created_by     uuid references public.users(id) on delete set null,
  updated_date   timestamptz not null default now(),
  updated_by     uuid references public.users(id) on delete set null,
  status         text not null default 'active' check (status in ('active','inactive'))
);

-- 3.2 mst_coupon
create table if not exists public.mst_coupon (
  id               uuid primary key default gen_random_uuid(),
  code             text not null unique,
  discount_type    text not null check (discount_type in ('percent','flat')),
  discount_value   integer not null check (discount_value > 0),
  max_redemptions  integer check (max_redemptions is null or max_redemptions >= 0),
  times_redeemed   integer not null default 0 check (times_redeemed >= 0),
  start_date       date,
  expiry_date      date,
  created_date     timestamptz not null default now(),
  created_by       uuid references public.users(id) on delete set null,
  updated_date     timestamptz not null default now(),
  updated_by       uuid references public.users(id) on delete set null,
  status           text not null default 'active' check (status in ('active','inactive')),
  constraint mst_coupon_percent_max check (discount_type <> 'percent' or discount_value <= 100),
  constraint mst_coupon_dates check (start_date is null or expiry_date is null or expiry_date >= start_date)
);

-- 3.3 mst_product
create table if not exists public.mst_product (
  id            uuid primary key default gen_random_uuid(),
  slug          text not null unique,
  name          text not null,
  category      text,
  ai_provider   text,
  is_active     boolean not null default true,
  start_date    date,
  end_date      date,
  created_date  timestamptz not null default now(),
  created_by    uuid references public.users(id) on delete set null,
  updated_date  timestamptz not null default now(),
  updated_by    uuid references public.users(id) on delete set null,
  status        text not null default 'active' check (status in ('active','inactive')),
  constraint mst_product_dates check (start_date is null or end_date is null or end_date >= start_date)
);

-- 3.4 mst_plan  (every plan belongs to a product)
create table if not exists public.mst_plan (
  id               uuid primary key default gen_random_uuid(),
  product_id       uuid not null references public.mst_product(id) on delete restrict,
  plan_interval    text not null check (plan_interval in ('monthly','quarterly','annual','enterprise')),
  duration_days    integer not null check (duration_days > 0),
  amount           integer not null check (amount >= 0),          -- paise (INR minor unit)
  currency         text not null default 'INR' check (char_length(currency) = 3),
  usage_limit      integer check (usage_limit is null or usage_limit >= 0),
  provider_plan_id text unique,                                   -- ER-DEVIATION: Razorpay plan_xxx (needed for autopay)
  start_date       date,
  end_date         date,
  expiry_date      date,
  created_date     timestamptz not null default now(),
  created_by       uuid references public.users(id) on delete set null,
  updated_date     timestamptz not null default now(),
  updated_by       uuid references public.users(id) on delete set null,
  status           text not null default 'active' check (status in ('active','inactive')),
  constraint mst_plan_dates check (start_date is null or end_date is null or end_date >= start_date)
);

-- 3.5 orders
create table if not exists public.orders (
  id                  uuid primary key default gen_random_uuid(),
  user_id             uuid not null references public.users(id) on delete restrict,
  coupon_id           uuid references public.mst_coupon(id) on delete restrict,  -- nullable: one order = one coupon max
  order_status        text not null default 'pending'
                      check (order_status in ('pending','placed','failed')),
  payment_status      text not null default 'initiated'
                      check (payment_status in ('initiated','submitted','credited','debited')),
  payment_mode        text check (payment_mode in ('card','e-mandate','upi','netbanking')),  -- NULL until known
  payment_provider    text not null default 'razorpay' check (payment_provider in ('razorpay','stripe')),
  provider_order_id   text unique,                       -- Razorpay order_xxx
  provider_payment_id text,                              -- Razorpay pay_xxx
  zoho_invoice_id     text,
  signature_verified  boolean not null default false,
  amount              integer not null check (amount >= 0),   -- paise, final amount after coupon
  currency            text not null default 'INR' check (char_length(currency) = 3),
  created_date        timestamptz not null default now(),
  created_by          uuid references public.users(id) on delete set null,
  updated_date        timestamptz not null default now(),
  updated_by          uuid references public.users(id) on delete set null,
  status              text not null default 'active' check (status in ('active','inactive'))
);

-- 3.6 order_items
create table if not exists public.order_items (
  id            uuid primary key default gen_random_uuid(),
  order_id      uuid not null references public.orders(id) on delete cascade,
  plan_id       uuid not null references public.mst_plan(id) on delete restrict,
  amount        integer not null check (amount >= 0),    -- price paid for this plan at purchase time (paise)
  created_date  timestamptz not null default now(),
  created_by    uuid references public.users(id) on delete set null,
  updated_date  timestamptz not null default now(),
  updated_by    uuid references public.users(id) on delete set null,
  status        text not null default 'active' check (status in ('active','inactive')),
  constraint order_items_order_plan_uk unique (order_id, plan_id)
);

-- 3.7 subscriptions
create table if not exists public.subscriptions (
  id                       uuid primary key default gen_random_uuid(),
  user_id                  uuid not null references public.users(id) on delete restrict,
  product_id               uuid not null references public.mst_product(id) on delete restrict,
  plan_id                  uuid not null references public.mst_plan(id) on delete restrict,
  order_id                 uuid not null references public.orders(id) on delete restrict,
  subscription_status      text not null default 'active'
                           check (subscription_status in ('active','expired','cancelled','refunded')),
  starts_at                timestamptz not null default now(),
  expires_at               timestamptz,
  auto_renew               boolean not null default false,
  provider_subscription_id text unique,                  -- Razorpay sub_xxx (autopay only)
  payment_method           text,
  auth_status              text,                         -- raw Razorpay subscription status
  next_charge_at           timestamptz,
  created_date             timestamptz not null default now(),
  created_by               uuid references public.users(id) on delete set null,
  updated_date             timestamptz not null default now(),
  updated_by               uuid references public.users(id) on delete set null,
  status                   text not null default 'active' check (status in ('active','inactive')),
  constraint subscriptions_order_plan_uk unique (order_id, plan_id),
  constraint subscriptions_dates check (expires_at is null or expires_at > starts_at)
);

-- 3.8 subscription_payments
-- ER-DEVIATION: the ER has two columns named "status". The first one is
-- renamed payment_status; the audit-style "status" stays as "status".
create table if not exists public.subscription_payments (
  id                  uuid primary key default gen_random_uuid(),
  subscription_id     uuid not null references public.subscriptions(id) on delete restrict,
  provider_payment_id text not null unique,              -- Razorpay pay_xxx -> webhook idempotency
  amount              integer not null check (amount >= 0),
  payment_status      text not null default 'captured'
                      check (payment_status in ('captured','failed','refunded')),
  payment_date        timestamptz,
  created_date        timestamptz not null default now(),
  created_by          uuid references public.users(id) on delete set null,
  updated_date        timestamptz not null default now(),
  updated_by          uuid references public.users(id) on delete set null,
  status              text not null default 'active' check (status in ('active','inactive'))
);

-- 3.9 notifications
create table if not exists public.notifications (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references public.users(id) on delete cascade,
  channel          text not null,
  sent_at          timestamptz,
  delivery_status  text not null default 'pending',
  created_date     timestamptz not null default now(),
  created_by       uuid references public.users(id) on delete set null,
  updated_date     timestamptz not null default now(),
  updated_by       uuid references public.users(id) on delete set null,
  status           text not null default 'active' check (status in ('active','inactive'))
);

-- 3.10 otp_verifications  (replaces the code's email_otps table)
create table if not exists public.otp_verifications (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references public.users(id) on delete cascade,
  otp_hash      text not null,
  purpose       text not null,
  attempts      integer not null default 0 check (attempts >= 0),
  expires_at    timestamptz not null,
  created_date  timestamptz not null default now(),
  created_by    uuid references public.users(id) on delete set null,
  updated_date  timestamptz not null default now(),
  updated_by    uuid references public.users(id) on delete set null,
  status        text not null default 'active' check (status in ('active','inactive'))
);

-- 3.11 refresh_tokens  (NOT used by current code: Supabase Auth owns sessions)
create table if not exists public.refresh_tokens (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references public.users(id) on delete cascade,
  token_hash       text not null unique,
  revoked          boolean not null default false,
  replaced_by_id   uuid references public.refresh_tokens(id) on delete set null,
  expires_at       timestamptz not null,
  created_date     timestamptz not null default now(),
  created_by       uuid references public.users(id) on delete set null,
  updated_date     timestamptz not null default now(),
  updated_by       uuid references public.users(id) on delete set null,
  status           text not null default 'active' check (status in ('active','inactive'))
);

-- 3.12 user_activity_log
create table if not exists public.user_activity_log (
  id             uuid primary key default gen_random_uuid(),
  actor_user_id  uuid references public.users(id) on delete set null,
  action         text not null,
  entity_type    text,
  entity_id      uuid,
  metadata       jsonb not null default '{}'::jsonb,
  created_date   timestamptz not null default now(),
  created_by     uuid references public.users(id) on delete set null,
  updated_date   timestamptz not null default now(),
  updated_by     uuid references public.users(id) on delete set null,
  status         text not null default 'active' check (status in ('active','inactive'))
);

-- 3.13 oauth_accounts  (NOT used by current code: Supabase Auth owns OAuth identities)
create table if not exists public.oauth_accounts (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid not null references public.users(id) on delete cascade,
  provider          text not null,
  provider_user_id  text not null,
  created_date      timestamptz not null default now(),
  created_by        uuid references public.users(id) on delete set null,
  updated_date      timestamptz not null default now(),
  updated_by        uuid references public.users(id) on delete set null,
  status            text not null default 'active' check (status in ('active','inactive')),
  constraint oauth_accounts_provider_uk unique (provider, provider_user_id)
);

-- 3.14 webhook_events  (ER-DEVIATION: only table NOT in the ER. Event-level dedupe + audit.)
create table if not exists public.webhook_events (
  id            uuid primary key default gen_random_uuid(),
  event_id      text not null unique,                    -- header X-Razorpay-Event-Id
  event_type    text not null,
  payload       jsonb not null,
  received_at   timestamptz not null default now(),
  processed_at  timestamptz,
  error         text
);

-- ============================================================================
-- 4. INDEXES  (every FK + lookup columns used by the code)
-- ============================================================================
create unique index if not exists orders_provider_payment_uk
  on public.orders (provider_payment_id) where provider_payment_id is not null;
create index if not exists orders_user_id_idx            on public.orders (user_id);
create index if not exists orders_coupon_id_idx          on public.orders (coupon_id);
create index if not exists order_items_order_id_idx      on public.order_items (order_id);
create index if not exists order_items_plan_id_idx       on public.order_items (plan_id);
create index if not exists mst_plan_product_id_idx       on public.mst_plan (product_id);
create index if not exists subscriptions_user_id_idx     on public.subscriptions (user_id);
create index if not exists subscriptions_product_id_idx  on public.subscriptions (product_id);
create index if not exists subscriptions_plan_id_idx     on public.subscriptions (plan_id);
create index if not exists subscriptions_expires_at_idx  on public.subscriptions (expires_at);
create index if not exists sub_payments_subscription_idx on public.subscription_payments (subscription_id);
create index if not exists notifications_user_id_idx     on public.notifications (user_id);
create index if not exists otp_user_purpose_idx          on public.otp_verifications (user_id, purpose, created_date desc);
create index if not exists refresh_tokens_user_id_idx    on public.refresh_tokens (user_id);
create index if not exists activity_actor_idx            on public.user_activity_log (actor_user_id);
create index if not exists activity_entity_idx           on public.user_activity_log (entity_type, entity_id);
create index if not exists oauth_accounts_user_id_idx    on public.oauth_accounts (user_id);

-- ============================================================================
-- 5. TRIGGERS
-- ============================================================================
-- 5.1 audit trigger on every table that has audit columns
do $$
declare t text;
begin
  foreach t in array array[
    'users','mst_coupon','mst_product','mst_plan','orders','order_items',
    'subscriptions','subscription_payments','notifications','otp_verifications',
    'refresh_tokens','user_activity_log','oauth_accounts'
  ]
  loop
    execute format('drop trigger if exists trg_%1$s_audit on public.%1$I', t);
    execute format(
      'create trigger trg_%1$s_audit before insert or update on public.%1$I
         for each row execute function public.set_audit_fields()', t);
  end loop;
end $$;

-- 5.2 auth.users -> public.users sync (REPLACES the old handle_new_user that wrote profiles)
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.users (id, email, full_name, mobile, email_verified)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    new.raw_user_meta_data->>'mobile',
    new.email_confirmed_at is not null
  )
  on conflict (id) do update
    set email = excluded.email,
        full_name = excluded.full_name,
        mobile = excluded.mobile,
        email_verified = excluded.email_verified;

  -- keep the legacy profiles table alive until the backend cut-over is finished
  if to_regclass('public.profiles') is not null then
    insert into public.profiles (id, full_name, mobile)
    values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''), new.raw_user_meta_data->>'mobile')
    on conflict (id) do update
      set full_name = excluded.full_name, mobile = excluded.mobile, updated_at = now();
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

create or replace function public.handle_auth_user_updated()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.users
     set email          = new.email,
         email_verified = (new.email_confirmed_at is not null),
         full_name      = coalesce(new.raw_user_meta_data->>'full_name', full_name),
         mobile         = coalesce(new.raw_user_meta_data->>'mobile', mobile)
   where id = new.id;
  return new;
end;
$$;

drop trigger if exists on_auth_user_updated on auth.users;
create trigger on_auth_user_updated
after update of email, email_confirmed_at, raw_user_meta_data on auth.users
for each row execute function public.handle_auth_user_updated();

-- ============================================================================
-- 6. BUSINESS FUNCTIONS (called by FastAPI via /rest/v1/rpc/<name> with the secret key)
--    Each runs in ONE transaction and is idempotent.
-- ============================================================================

-- 6.1 One-time payment succeeded (called by /verify AND by webhook payment.captured)
create or replace function public.apply_payment_success(
  p_provider_order_id   text,
  p_provider_payment_id text,
  p_payment_mode        text    default null,
  p_amount              integer default null,
  p_signature_verified  boolean default false
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_order public.orders%rowtype;
  v_first boolean;
  v_mode  text;
begin
  select * into v_order from public.orders
   where provider_order_id = p_provider_order_id for update;
  if not found then
    raise exception 'ORDER_NOT_FOUND: %', p_provider_order_id using errcode = 'P0002';
  end if;

  if p_amount is not null and p_amount <> v_order.amount then
    raise exception 'AMOUNT_MISMATCH: order % expects %, got %', v_order.id, v_order.amount, p_amount
      using errcode = 'P0003';
  end if;

  v_mode := case lower(coalesce(p_payment_mode, ''))
              when 'emandate'   then 'e-mandate'
              when 'e-mandate'  then 'e-mandate'
              when 'card'       then 'card'
              when 'upi'        then 'upi'
              when 'netbanking' then 'netbanking'
              else null end;

  v_first := (v_order.order_status <> 'placed');

  update public.orders
     set order_status        = 'placed',
         payment_status      = 'credited',
         provider_payment_id = coalesce(provider_payment_id, p_provider_payment_id),
         payment_mode        = coalesce(v_mode, payment_mode),
         signature_verified  = signature_verified or coalesce(p_signature_verified, false)
   where id = v_order.id;

  if v_first then
    insert into public.subscriptions
      (user_id, product_id, plan_id, order_id, subscription_status, starts_at, expires_at, auto_renew)
    select v_order.user_id, p.product_id, oi.plan_id, v_order.id, 'active',
           now(), now() + make_interval(days => p.duration_days), false
      from public.order_items oi
      join public.mst_plan p on p.id = oi.plan_id
     where oi.order_id = v_order.id
    on conflict (order_id, plan_id) do nothing;

    if v_order.coupon_id is not null then
      update public.mst_coupon set times_redeemed = times_redeemed + 1 where id = v_order.coupon_id;
    end if;
  end if;

  return v_order.id;
end;
$$;

-- 6.2 Payment failed (webhook payment.failed). Never downgrades a placed order.
create or replace function public.apply_payment_failure(
  p_provider_order_id text
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare v_id uuid;
begin
  update public.orders
     set order_status = 'failed'
   where provider_order_id = p_provider_order_id
     and order_status <> 'placed'
  returning id into v_id;
  return v_id;
end;
$$;

-- 6.3 Autopay charge succeeded (webhook subscription.charged). Creates the subscription
--     on the first charge, extends it on later charges, records the payment once.
create or replace function public.apply_subscription_charged(
  p_order_id                 uuid,
  p_provider_subscription_id text,
  p_provider_payment_id      text,
  p_provider_order_id        text,
  p_amount                   integer,
  p_paid_at                  timestamptz default null,
  p_current_end              timestamptz default null,
  p_charge_at                timestamptz default null,
  p_payment_method           text        default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_order public.orders%rowtype;
  v_plan  record;
  v_sub   uuid;
  v_first boolean;
  v_paid  timestamptz := coalesce(p_paid_at, now());
begin
  select * into v_order from public.orders where id = p_order_id for update;
  if not found then
    raise exception 'ORDER_NOT_FOUND: %', p_order_id using errcode = 'P0002';
  end if;

  select oi.plan_id, p.product_id, p.duration_days
    into v_plan
    from public.order_items oi
    join public.mst_plan p on p.id = oi.plan_id
   where oi.order_id = v_order.id
   order by oi.created_date
   limit 1;
  if not found then
    raise exception 'ORDER_HAS_NO_ITEMS: %', v_order.id using errcode = 'P0002';
  end if;

  v_first := (v_order.order_status <> 'placed');
  if v_first and p_amount <> v_order.amount then
    raise exception 'AMOUNT_MISMATCH: order % expects %, got %', v_order.id, v_order.amount, p_amount
      using errcode = 'P0003';
  end if;

  insert into public.subscriptions
    (user_id, product_id, plan_id, order_id, subscription_status, starts_at, expires_at,
     auto_renew, provider_subscription_id, payment_method, auth_status, next_charge_at)
  values
    (v_order.user_id, v_plan.product_id, v_plan.plan_id, v_order.id, 'active', v_paid,
     coalesce(p_current_end, v_paid + make_interval(days => v_plan.duration_days)),
     true, p_provider_subscription_id, p_payment_method, 'active', p_charge_at)
  on conflict (provider_subscription_id) do update
    set subscription_status = 'active',
        expires_at          = greatest(subscriptions.expires_at, excluded.expires_at),
        next_charge_at      = excluded.next_charge_at,
        auth_status         = 'active',
        auto_renew          = true
  returning id into v_sub;

  insert into public.subscription_payments
    (subscription_id, provider_payment_id, amount, payment_status, payment_date)
  values (v_sub, p_provider_payment_id, p_amount, 'captured', v_paid)
  on conflict (provider_payment_id) do nothing;

  update public.orders
     set order_status        = 'placed',
         payment_status      = 'credited',
         payment_mode        = coalesce(payment_mode, 'e-mandate'),
         provider_order_id   = coalesce(provider_order_id, p_provider_order_id),
         provider_payment_id = coalesce(provider_payment_id, p_provider_payment_id)
   where id = v_order.id;

  if v_first and v_order.coupon_id is not null then
    update public.mst_coupon set times_redeemed = times_redeemed + 1 where id = v_order.coupon_id;
  end if;

  return v_sub;
end;
$$;

-- 6.4 Subscription lifecycle event (authenticated / activated / pending / halted / cancelled / completed)
--     Does nothing if the local subscription does not exist yet (it is created by 6.3).
--     Ignores late "active-ish" events after cancellation (out-of-order protection).
create or replace function public.apply_subscription_status(
  p_provider_subscription_id text,
  p_provider_status          text,
  p_charge_at                timestamptz default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare v_id uuid;
begin
  update public.subscriptions s
     set auth_status         = p_provider_status,
         subscription_status = case p_provider_status
                                 when 'cancelled' then 'cancelled'
                                 when 'completed' then 'expired'
                                 when 'halted'    then 'expired'
                                 else s.subscription_status end,
         auto_renew          = (p_provider_status in ('active','authenticated')),
         next_charge_at      = coalesce(p_charge_at, s.next_charge_at)
   where s.provider_subscription_id = p_provider_subscription_id
     and not (s.subscription_status in ('cancelled','refunded')
              and p_provider_status in ('created','authenticated','active','pending'))
  returning s.id into v_id;
  return v_id;
end;
$$;

-- 6.5 Webhook dedupe: returns TRUE if this event_id is new (caller should process it)
create or replace function public.register_webhook_event(
  p_event_id   text,
  p_event_type text,
  p_payload    jsonb
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_id uuid;
begin
  insert into public.webhook_events (event_id, event_type, payload)
  values (p_event_id, p_event_type, p_payload)
  on conflict (event_id) do nothing
  returning id into v_id;
  return v_id is not null;
end;
$$;

-- 6.6 Admin check used by RLS
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.users u
     where u.id = auth.uid()
       and u.role = 'admin'
       and u.account_status = 'active'
       and u.deleted_at is null
  );
$$;

-- Function privileges: business functions are backend-only.
revoke execute on function public.apply_payment_success(text,text,text,integer,boolean) from public, anon, authenticated;
revoke execute on function public.apply_payment_failure(text) from public, anon, authenticated;
revoke execute on function public.apply_subscription_charged(uuid,text,text,text,integer,timestamptz,timestamptz,timestamptz,text) from public, anon, authenticated;
revoke execute on function public.apply_subscription_status(text,text,timestamptz) from public, anon, authenticated;
revoke execute on function public.register_webhook_event(text,text,jsonb) from public, anon, authenticated;
revoke execute on function public.is_admin() from public, anon;

grant execute on function public.apply_payment_success(text,text,text,integer,boolean) to service_role;
grant execute on function public.apply_payment_failure(text) to service_role;
grant execute on function public.apply_subscription_charged(uuid,text,text,text,integer,timestamptz,timestamptz,timestamptz,text) to service_role;
grant execute on function public.apply_subscription_status(text,text,timestamptz) to service_role;
grant execute on function public.register_webhook_event(text,text,jsonb) to service_role;
grant execute on function public.is_admin() to authenticated, service_role;

-- ============================================================================
-- 7. RLS: ENABLE
-- ============================================================================
alter table public.users                 enable row level security;
alter table public.mst_coupon            enable row level security;
alter table public.mst_product           enable row level security;
alter table public.mst_plan              enable row level security;
alter table public.orders                enable row level security;
alter table public.order_items           enable row level security;
alter table public.subscriptions         enable row level security;
alter table public.subscription_payments enable row level security;
alter table public.notifications         enable row level security;
alter table public.otp_verifications     enable row level security;
alter table public.refresh_tokens        enable row level security;
alter table public.user_activity_log     enable row level security;
alter table public.oauth_accounts        enable row level security;
alter table public.webhook_events        enable row level security;

-- ============================================================================
-- 8. TABLE PRIVILEGES + POLICIES
--    The backend uses the secret key (service_role, BYPASSRLS) -> never blocked.
--    Browser/user JWT (role authenticated) gets read-own only.
-- ============================================================================
grant all on all tables in schema public to service_role;

-- anon: no access to anything
revoke all on public.users, public.mst_coupon, public.mst_product, public.mst_plan,
              public.orders, public.order_items, public.subscriptions,
              public.subscription_payments, public.notifications, public.otp_verifications,
              public.refresh_tokens, public.user_activity_log, public.oauth_accounts,
              public.webhook_events
  from anon;

-- authenticated: no writes on transactional/system tables (backend writes them)
revoke insert, update, delete on public.orders, public.order_items, public.subscriptions,
              public.subscription_payments, public.notifications
  from authenticated;
revoke all on public.otp_verifications, public.refresh_tokens, public.oauth_accounts,
              public.webhook_events, public.user_activity_log, public.mst_coupon
  from authenticated;

-- users: user may update ONLY full_name and mobile on own row
revoke insert, delete on public.users from authenticated;
revoke update on public.users from authenticated;
grant  update (full_name, mobile) on public.users to authenticated;

drop policy if exists users_select_own on public.users;
create policy users_select_own on public.users
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists users_update_own on public.users;
create policy users_update_own on public.users
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- mst_product / mst_plan: authenticated read active rows; admin full access
drop policy if exists mst_product_select on public.mst_product;
create policy mst_product_select on public.mst_product
  for select to authenticated
  using ((is_active and status = 'active') or public.is_admin());

drop policy if exists mst_product_admin_insert on public.mst_product;
create policy mst_product_admin_insert on public.mst_product
  for insert to authenticated with check (public.is_admin());
drop policy if exists mst_product_admin_update on public.mst_product;
create policy mst_product_admin_update on public.mst_product
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists mst_product_admin_delete on public.mst_product;
create policy mst_product_admin_delete on public.mst_product
  for delete to authenticated using (public.is_admin());

drop policy if exists mst_plan_select on public.mst_plan;
create policy mst_plan_select on public.mst_plan
  for select to authenticated
  using (status = 'active' or public.is_admin());

drop policy if exists mst_plan_admin_insert on public.mst_plan;
create policy mst_plan_admin_insert on public.mst_plan
  for insert to authenticated with check (public.is_admin());
drop policy if exists mst_plan_admin_update on public.mst_plan;
create policy mst_plan_admin_update on public.mst_plan
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists mst_plan_admin_delete on public.mst_plan;
create policy mst_plan_admin_delete on public.mst_plan
  for delete to authenticated using (public.is_admin());

-- mst_coupon: admin only (users must not enumerate codes; backend validates codes)
grant select, insert, update, delete on public.mst_coupon to authenticated;
drop policy if exists mst_coupon_admin_select on public.mst_coupon;
create policy mst_coupon_admin_select on public.mst_coupon
  for select to authenticated using (public.is_admin());
drop policy if exists mst_coupon_admin_insert on public.mst_coupon;
create policy mst_coupon_admin_insert on public.mst_coupon
  for insert to authenticated with check (public.is_admin());
drop policy if exists mst_coupon_admin_update on public.mst_coupon;
create policy mst_coupon_admin_update on public.mst_coupon
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists mst_coupon_admin_delete on public.mst_coupon;
create policy mst_coupon_admin_delete on public.mst_coupon
  for delete to authenticated using (public.is_admin());

-- orders / order_items / subscriptions / subscription_payments / notifications: read own (admin reads all)
drop policy if exists orders_select_own on public.orders;
create policy orders_select_own on public.orders
  for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

drop policy if exists order_items_select_own on public.order_items;
create policy order_items_select_own on public.order_items
  for select to authenticated
  using (
    public.is_admin()
    or exists (select 1 from public.orders o where o.id = order_items.order_id and o.user_id = auth.uid())
  );

drop policy if exists subscriptions_select_own on public.subscriptions;
create policy subscriptions_select_own on public.subscriptions
  for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

drop policy if exists sub_payments_select_own on public.subscription_payments;
create policy sub_payments_select_own on public.subscription_payments
  for select to authenticated
  using (
    public.is_admin()
    or exists (select 1 from public.subscriptions s
                where s.id = subscription_payments.subscription_id and s.user_id = auth.uid())
  );

drop policy if exists notifications_select_own on public.notifications;
create policy notifications_select_own on public.notifications
  for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

-- user_activity_log: admin read only
grant select on public.user_activity_log to authenticated;
drop policy if exists activity_admin_select on public.user_activity_log;
create policy activity_admin_select on public.user_activity_log
  for select to authenticated using (public.is_admin());

-- otp_verifications, refresh_tokens, oauth_accounts, webhook_events:
-- RLS ON, NO policies, no grants -> only the backend (service_role) can touch them.

-- ============================================================================
-- 9. SEED DATA  (TEST SEED - confirm DECISION 3 and 4 in the plan before production)
--    Amounts are paise and match Backend/routes/payments.py SERVICE_PRICES x 100.
-- ============================================================================
insert into public.mst_product (slug, name, category) values
  ('career-toolkit',    'Career Toolkit',    'career'),
  ('portfolio-review',  'Portfolio Review',  'career'),
  ('career-roadmap',    'Career Roadmap',    'career'),
  ('beevolve-premium',  'Beevolve Premium Plan', 'subscription')
on conflict (slug) do nothing;

insert into public.mst_plan (product_id, plan_interval, duration_days, amount, currency)
select p.id, v.plan_interval, v.duration_days, v.amount, 'INR'
  from (values
    ('career-toolkit',   'annual',  365, 49900),
    ('portfolio-review', 'annual',  365, 29900),
    ('career-roadmap',   'annual',  365, 19900),
    ('beevolve-premium', 'monthly',  30, 50000)
  ) as v(slug, plan_interval, duration_days, amount)
  join public.mst_product p on p.slug = v.slug
 where not exists (select 1 from public.mst_plan x where x.product_id = p.id);
