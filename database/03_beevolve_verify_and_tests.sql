-- ============================================================================
-- BeEvolve  |  03_beevolve_verify_and_tests.sql
-- Run PART 1 (verification) and PART 2 (tests) after 01 and 02.
-- PART 2 creates temp functions only and rolls back ALL test data (no residue).
-- Run PART 2 as ONE script in the SQL Editor (it needs a single session).
-- ============================================================================

-- ############################ PART 1: VERIFICATION ##########################

-- 1.1 Tables: expect 14 rows, all present = true
select t.table_name,
       exists (select 1 from information_schema.tables i
                where i.table_schema = 'public' and i.table_name = t.table_name) as present
  from (values ('users'),('mst_coupon'),('mst_product'),('mst_plan'),('orders'),('order_items'),
               ('subscriptions'),('subscription_payments'),('notifications'),('otp_verifications'),
               ('refresh_tokens'),('user_activity_log'),('oauth_accounts'),('webhook_events')) as t(table_name)
 order by 1;

-- 1.2 Column counts: every row must show ok = true
select e.table_name, e.expected_cols, count(c.column_name) as actual_cols,
       (e.expected_cols = count(c.column_name)) as ok
  from (values ('users',15),('mst_coupon',13),('mst_product',13),('mst_plan',16),('orders',18),
               ('order_items',9),('subscriptions',18),('subscription_payments',11),
               ('notifications',10),('otp_verifications',11),('refresh_tokens',11),
               ('user_activity_log',11),('oauth_accounts',9),('webhook_events',7)) as e(table_name, expected_cols)
  left join information_schema.columns c
         on c.table_schema = 'public' and c.table_name = e.table_name
 group by e.table_name, e.expected_cols
 order by 1;

-- 1.3 Primary keys: expect 0 rows (a row = table without PK)
select c.relname as table_without_pk
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind = 'r'
   and c.relname in ('users','mst_coupon','mst_product','mst_plan','orders','order_items',
                     'subscriptions','subscription_payments','notifications','otp_verifications',
                     'refresh_tokens','user_activity_log','oauth_accounts','webhook_events')
   and not exists (select 1 from pg_constraint k where k.conrelid = c.oid and k.contype = 'p');

-- 1.4 Foreign keys: expect 0 rows (a row = required FK missing)
select r.tbl, r.col, r.ref_tbl as missing_fk
  from (values
    ('orders','user_id','users'),('orders','coupon_id','mst_coupon'),
    ('order_items','order_id','orders'),('order_items','plan_id','mst_plan'),
    ('mst_plan','product_id','mst_product'),
    ('subscriptions','user_id','users'),('subscriptions','product_id','mst_product'),
    ('subscriptions','plan_id','mst_plan'),('subscriptions','order_id','orders'),
    ('subscription_payments','subscription_id','subscriptions'),
    ('notifications','user_id','users'),('otp_verifications','user_id','users'),
    ('refresh_tokens','user_id','users'),('refresh_tokens','replaced_by_id','refresh_tokens'),
    ('user_activity_log','actor_user_id','users'),('oauth_accounts','user_id','users'),
    ('users','created_by','users'),('users','updated_by','users'),
    ('mst_coupon','created_by','users'),('mst_product','created_by','users'),
    ('mst_plan','created_by','users'),('orders','created_by','users'),
    ('order_items','created_by','users'),('subscriptions','created_by','users'),
    ('subscription_payments','created_by','users')
  ) as r(tbl, col, ref_tbl)
 where not exists (
   select 1
     from pg_constraint k
     join pg_class t  on t.oid  = k.conrelid  and t.relname  = r.tbl
     join pg_class rt on rt.oid = k.confrelid and rt.relname = r.ref_tbl
     join pg_attribute a on a.attrelid = k.conrelid and a.attnum = any (k.conkey) and a.attname = r.col
    where k.contype = 'f');

-- 1.5 CHECK / UNIQUE constraints: read the list and compare with the plan (section 2)
select conrelid::regclass as table_name, conname, contype, pg_get_constraintdef(oid) as definition
  from pg_constraint
 where connamespace = 'public'::regnamespace and contype in ('c','u')
 order by 1, 3, 2;

-- 1.6 Indexes
select tablename, indexname, indexdef
  from pg_indexes where schemaname = 'public'
   and tablename in ('users','mst_coupon','mst_product','mst_plan','orders','order_items',
                     'subscriptions','subscription_payments','notifications','otp_verifications',
                     'refresh_tokens','user_activity_log','oauth_accounts','webhook_events')
 order by 1, 2;

-- 1.7 Triggers: expect audit_triggers = 13 and auth_triggers = 2
select (select count(*) from pg_trigger where tgname like 'trg\_%\_audit' and not tgisinternal) as audit_triggers,
       (select count(*) from pg_trigger where tgname in ('on_auth_user_created','on_auth_user_updated')
                                          and not tgisinternal) as auth_triggers;

-- 1.8 RLS: expect 0 rows (a row = table without RLS)
select relname as table_without_rls
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity
   and c.relname in ('users','mst_coupon','mst_product','mst_plan','orders','order_items',
                     'subscriptions','subscription_payments','notifications','otp_verifications',
                     'refresh_tokens','user_activity_log','oauth_accounts','webhook_events');

-- 1.9 Policies: compare with plan section 11
select tablename, policyname, cmd, roles, qual, with_check
  from pg_policies where schemaname = 'public' order by tablename, cmd, policyname;

-- 1.10 Function privileges: anon/authenticated must be false, service_role true
select f.fn,
       has_function_privilege('anon', f.fn, 'execute')          as anon_can_run,
       has_function_privilege('authenticated', f.fn, 'execute') as authenticated_can_run,
       has_function_privilege('service_role', f.fn, 'execute')  as service_role_can_run
  from (values
    ('public.apply_payment_success(text,text,text,integer,boolean)'),
    ('public.apply_payment_failure(text)'),
    ('public.apply_subscription_charged(uuid,text,text,text,integer,timestamptz,timestamptz,timestamptz,text)'),
    ('public.apply_subscription_status(text,text,timestamptz)'),
    ('public.register_webhook_event(text,text,jsonb)')
  ) as f(fn);

-- 1.11 Seed data: expect 4 products, 4 plans
select (select count(*) from public.mst_product) as products,
       (select count(*) from public.mst_plan)    as plans;

-- ############################ PART 2: DATABASE TESTS ########################
-- Output: one line per test:  name | expected | PASS/FAIL
-- Every line must end in PASS.

create or replace function pg_temp.t(
  p_name   text,
  p_sql    text,
  p_expect text,            -- 'ok' | 'count=N' | 'rows=N' | an SQLSTATE e.g. '23505'
  p_role   text default null,   -- null = current role (postgres) | 'authenticated' | 'anon'
  p_uid    uuid default null
) returns text
language plpgsql
as $$
declare v_n bigint; v_out text;
begin
  if p_role is not null then
    if p_uid is not null then
      perform set_config('request.jwt.claims',
              json_build_object('sub', p_uid, 'role', p_role)::text, true);
      perform set_config('request.jwt.claim.sub', p_uid::text, true);
    end if;
    execute format('set local role %I', p_role);
  end if;

  if p_expect like 'count=%' then
    execute p_sql into v_n;
    v_out := case when v_n = substr(p_expect, 7)::bigint then 'PASS' else 'FAIL (count=' || v_n || ')' end;
  elsif p_expect like 'rows=%' then
    execute p_sql;
    get diagnostics v_n = row_count;
    v_out := case when v_n = substr(p_expect, 6)::bigint then 'PASS' else 'FAIL (rows=' || v_n || ')' end;
  elsif p_expect = 'ok' then
    execute p_sql;
    v_out := 'PASS';
  else
    execute p_sql;
    v_out := 'FAIL (no error raised)';
  end if;

  execute 'reset role';
  return format('%-52s | expected %-9s | %s', p_name, p_expect, v_out);
exception when others then
  execute 'reset role';
  if sqlstate = p_expect then
    return format('%-52s | expected %-9s | PASS', p_name, p_expect);
  end if;
  return format('%-52s | expected %-9s | FAIL (got %s: %s)', p_name, p_expect, sqlstate, sqlerrm);
end;
$$;

create or replace function pg_temp.run_db_tests()
returns setof text
language plpgsql
as $$
declare
  a uuid := gen_random_uuid();
  b uuid := gen_random_uuid();
  c uuid := gen_random_uuid();
  v_plan uuid; v_prod uuid; v_amt integer;
  v_coupon uuid; oa uuid; ob uuid; v_sub uuid;
  v_n integer;
  v_res text[] := '{}';
begin
  begin
    -- ---------- setup (rolled back at the end) ----------
    insert into auth.users (id, email, raw_user_meta_data) values
      (a, 'a_' || a || '@t.test', '{"full_name":"User A"}'),
      (b, 'b_' || b || '@t.test', '{"full_name":"User B"}'),
      (c, 'c_' || c || '@t.test', '{"full_name":"Admin C"}');
    update public.users set role = 'admin' where id = c;

    select p.id, p.product_id, p.amount into v_plan, v_prod, v_amt
      from public.mst_plan p join public.mst_product pr on pr.id = p.product_id
     where pr.slug = 'career-toolkit' limit 1;

    insert into public.mst_coupon (code, discount_type, discount_value, max_redemptions)
    values ('T_' || a, 'percent', 10, 5) returning id into v_coupon;

    -- 1. VALID INSERTS
    v_res := v_res || pg_temp.t('valid insert: order A',
      format($q$insert into public.orders (user_id, coupon_id, provider_order_id, amount)
                values (%L, %L, 'order_t_a', %s)$q$, a, v_coupon, v_amt), 'ok');
    select id into oa from public.orders where provider_order_id = 'order_t_a';
    v_res := v_res || pg_temp.t('valid insert: order_item A',
      format('insert into public.order_items (order_id, plan_id, amount) values (%L, %L, %s)', oa, v_plan, v_amt), 'ok');
    insert into public.orders (user_id, provider_order_id, amount) values (b, 'order_t_b', v_amt) returning id into ob;

    -- 2. INVALID FK
    v_res := v_res || pg_temp.t('invalid FK: order with unknown user',
      format($q$insert into public.orders (user_id, provider_order_id, amount) values (%L, 'order_t_x', 100)$q$, gen_random_uuid()), '23503');
    v_res := v_res || pg_temp.t('invalid FK: order_item with unknown plan',
      format('insert into public.order_items (order_id, plan_id, amount) values (%L, %L, 1)', oa, gen_random_uuid()), '23503');

    -- 3. DUPLICATE UNIQUE
    v_res := v_res || pg_temp.t('duplicate: provider_order_id',
      format($q$insert into public.orders (user_id, provider_order_id, amount) values (%L, 'order_t_a', 100)$q$, a), '23505');
    v_res := v_res || pg_temp.t('duplicate: coupon code',
      format($q$insert into public.mst_coupon (code, discount_type, discount_value) values ('T_%s','flat',10)$q$, a), '23505');
    v_res := v_res || pg_temp.t('duplicate: product slug',
      $q$insert into public.mst_product (slug, name) values ('career-toolkit','dup')$q$, '23505');
    v_res := v_res || pg_temp.t('duplicate: (order_id, plan_id) in order_items',
      format('insert into public.order_items (order_id, plan_id, amount) values (%L, %L, %s)', oa, v_plan, v_amt), '23505');

    -- 4. NULL REQUIRED FIELD
    v_res := v_res || pg_temp.t('NULL: orders.user_id',
      $q$insert into public.orders (user_id, provider_order_id, amount) values (null, 'order_t_n', 100)$q$, '23502');
    v_res := v_res || pg_temp.t('NULL: mst_plan.product_id',
      $q$insert into public.mst_plan (product_id, plan_interval, duration_days, amount) values (null,'monthly',30,100)$q$, '23502');
    v_res := v_res || pg_temp.t('NULL: users.email',
      format('insert into public.users (id, email) values (%L, null)', gen_random_uuid()), '23502');

    -- 5. INVALID STATUS / ENUM
    v_res := v_res || pg_temp.t('invalid status: orders.order_status',
      format($q$insert into public.orders (user_id, provider_order_id, amount, order_status) values (%L,'order_t_s',100,'bogus')$q$, a), '23514');
    v_res := v_res || pg_temp.t('invalid status: orders.payment_status',
      format($q$insert into public.orders (user_id, provider_order_id, amount, payment_status) values (%L,'order_t_s2',100,'bogus')$q$, a), '23514');
    v_res := v_res || pg_temp.t('invalid status: subscriptions.subscription_status',
      format($q$insert into public.subscriptions (user_id, product_id, plan_id, order_id, subscription_status)
                values (%L,%L,%L,%L,'bogus')$q$, a, v_prod, v_plan, ob), '23514');
    v_res := v_res || pg_temp.t('invalid status: mst_plan.plan_interval',
      format($q$insert into public.mst_plan (product_id, plan_interval, duration_days, amount) values (%L,'weekly',7,100)$q$, v_prod), '23514');
    v_res := v_res || pg_temp.t('invalid enum: users.role',
      format($q$update public.users set role = 'superuser' where id = %L$q$, a), '22P02');

    -- 6. NEGATIVE / ILLEGAL AMOUNTS
    v_res := v_res || pg_temp.t('negative amount: orders.amount',
      format($q$insert into public.orders (user_id, provider_order_id, amount) values (%L,'order_t_neg',-1)$q$, a), '23514');
    v_res := v_res || pg_temp.t('negative amount: order_items.amount',
      format('insert into public.order_items (order_id, plan_id, amount) values (%L, %L, -5)', ob, v_plan), '23514');
    v_res := v_res || pg_temp.t('coupon percent > 100',
      $q$insert into public.mst_coupon (code, discount_type, discount_value) values ('T_BIG','percent',150)$q$, '23514');
    v_res := v_res || pg_temp.t('coupon expiry before start',
      $q$insert into public.mst_coupon (code, discount_type, discount_value, start_date, expiry_date)
         values ('T_DATE','flat',10, current_date, current_date - 1)$q$, '23514');

    -- 7. UPDATE
    v_res := v_res || pg_temp.t('update: order amount',
      format('update public.orders set amount = amount + 1 where id = %L', ob), 'rows=1');
    select count(*) into v_n from public.orders where id = ob and updated_date > created_date;
    v_res := v_res || format('%-52s | expected %-9s | %s', 'update: audit trigger bumped updated_date', 'count=1',
                             case when v_n = 1 then 'PASS' else 'FAIL' end);

    -- 8. DELETE
    v_res := v_res || pg_temp.t('delete: user that owns orders is blocked',
      format('delete from public.users where id = %L', a), '23503');
    v_res := v_res || pg_temp.t('delete: order_item (allowed)',
      format('delete from public.order_items where order_id = %L', oa), 'rows=1');
    insert into public.order_items (order_id, plan_id, amount) values (oa, v_plan, v_amt);

    -- 9. PAYMENT FUNCTIONS (idempotency, amount check)
    v_res := v_res || pg_temp.t('apply_payment_success: wrong amount rejected',
      format($q$select public.apply_payment_success('order_t_a','pay_t_1','upi',%s,true)$q$, v_amt + 1), 'P0003');
    perform public.apply_payment_success('order_t_a', 'pay_t_1', 'upi', v_amt, true);
    perform public.apply_payment_success('order_t_a', 'pay_t_1', 'upi', v_amt, true);   -- webhook replay
    select count(*) into v_n from public.subscriptions where order_id = oa;
    v_res := v_res || format('%-52s | expected %-9s | %s', 'apply_payment_success x2 -> exactly 1 subscription', 'count=1',
                             case when v_n = 1 then 'PASS' else 'FAIL (' || v_n || ')' end);
    select times_redeemed into v_n from public.mst_coupon where id = v_coupon;
    v_res := v_res || format('%-52s | expected %-9s | %s', 'apply_payment_success x2 -> coupon redeemed once', 'count=1',
                             case when v_n = 1 then 'PASS' else 'FAIL (' || v_n || ')' end);
    select count(*) into v_n from public.orders
     where id = oa and order_status = 'placed' and payment_status = 'credited'
       and provider_payment_id = 'pay_t_1' and payment_mode = 'upi' and signature_verified;
    v_res := v_res || format('%-52s | expected %-9s | %s', 'order is placed/credited with payment id + mode', 'count=1',
                             case when v_n = 1 then 'PASS' else 'FAIL' end);
    v_res := v_res || pg_temp.t('apply_payment_failure never downgrades placed order',
      $q$select public.apply_payment_failure('order_t_a')$q$, 'ok');
    select count(*) into v_n from public.orders where id = oa and order_status = 'placed';
    v_res := v_res || format('%-52s | expected %-9s | %s', 'order still placed after failure event', 'count=1',
                             case when v_n = 1 then 'PASS' else 'FAIL' end);

    select id into v_sub from public.subscriptions where order_id = oa limit 1;
    v_res := v_res || pg_temp.t('subscription_payments: first insert',
      format($q$insert into public.subscription_payments (subscription_id, provider_payment_id, amount) values (%L,'pay_dup',100)$q$, v_sub), 'ok');
    v_res := v_res || pg_temp.t('subscription_payments: duplicate provider_payment_id',
      format($q$insert into public.subscription_payments (subscription_id, provider_payment_id, amount) values (%L,'pay_dup',100)$q$, v_sub), '23505');
    v_res := v_res || pg_temp.t('webhook_events: first event id is new',
      $q$select public.register_webhook_event('evt_t_1','payment.captured','{}'::jsonb)$q$, 'ok');
    select count(*) into v_n from (select public.register_webhook_event('evt_t_1','payment.captured','{}'::jsonb) r) s where r = false;
    v_res := v_res || format('%-52s | expected %-9s | %s', 'webhook_events: replayed event id returns false', 'count=1',
                             case when v_n = 1 then 'PASS' else 'FAIL' end);

    -- 10. RLS / SECURITY  (User A, User B, Admin C, anon)
    v_res := v_res || pg_temp.t('A reads own orders',            format('select count(*) from public.orders where user_id = %L', a), 'count=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads B orders (must be 0)',   format('select count(*) from public.orders where user_id = %L', b), 'count=0', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads ALL orders (only own)',  'select count(*) from public.orders', 'count=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads own order_items',        'select count(*) from public.order_items', 'count=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads own subscriptions',      'select count(*) from public.subscriptions', 'count=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads own subscription_payments', 'select count(*) from public.subscription_payments', 'count=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads own user row',           format('select count(*) from public.users where id = %L', a), 'count=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads B user row (must be 0)', format('select count(*) from public.users where id = %L', b), 'count=0', 'authenticated', a);
    v_res := v_res || pg_temp.t('A updates own full_name',        format($q$update public.users set full_name = 'A2' where id = %L$q$, a), 'rows=1', 'authenticated', a);
    v_res := v_res || pg_temp.t('A updates B full_name (0 rows)', format($q$update public.users set full_name = 'HACK' where id = %L$q$, b), 'rows=0', 'authenticated', a);
    v_res := v_res || pg_temp.t('A promotes self to admin (blocked)', format($q$update public.users set role = 'admin' where id = %L$q$, a), '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A inserts an order (blocked)',   format($q$insert into public.orders (user_id, provider_order_id, amount) values (%L,'order_t_hack',1)$q$, a), '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A edits own order amount (blocked)', format('update public.orders set amount = 1 where id = %L', oa), '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A deletes own order (blocked)',  format('delete from public.orders where id = %L', oa), '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A inserts a subscription (blocked)', format($q$insert into public.subscriptions (user_id, product_id, plan_id, order_id) values (%L,%L,%L,%L)$q$, a, v_prod, v_plan, oa), '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads mst_coupon (blocked)',   'select count(*) from public.mst_coupon', '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads otp_verifications (blocked)', 'select count(*) from public.otp_verifications', '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads webhook_events (blocked)', 'select count(*) from public.webhook_events', '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads user_activity_log (sees 0 rows)', 'select count(*) from public.user_activity_log', 'count=0', 'authenticated', a);
    v_res := v_res || pg_temp.t('A calls apply_payment_success RPC (blocked)', $q$select public.apply_payment_success('order_t_b','pay_x','upi',1,true)$q$, '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('A reads active products',        'select 1 / nullif(count(*), 0) from public.mst_product', 'ok', 'authenticated', a);
    v_res := v_res || pg_temp.t('A inserts product (blocked by RLS)', $q$insert into public.mst_product (slug, name) values ('hack','hack')$q$, '42501', 'authenticated', a);
    v_res := v_res || pg_temp.t('Admin C reads A+B orders',       format('select count(*) from public.orders where user_id in (%L, %L)', a, b), 'count=2', 'authenticated', c);
    v_res := v_res || pg_temp.t('Admin C reads coupons',          format($q$select 1 / nullif(count(*), 0) from public.mst_coupon where id = %L$q$, v_coupon), 'ok', 'authenticated', c);
    v_res := v_res || pg_temp.t('Admin C inserts product',        $q$insert into public.mst_product (slug, name) values ('t-admin-prod','t')$q$, 'ok', 'authenticated', c);
    v_res := v_res || pg_temp.t('anon reads products (blocked)',  'select count(*) from public.mst_product', '42501', 'anon');
    v_res := v_res || pg_temp.t('anon reads users (blocked)',     'select count(*) from public.users', '42501', 'anon');
    v_res := v_res || pg_temp.t('anon reads orders (blocked)',    'select count(*) from public.orders', '42501', 'anon');

    raise exception 'ROLLBACK_TESTS' using errcode = 'P9999';
  exception
    when sqlstate 'P9999' then null;              -- normal end: all test data rolled back
    when others then
      v_res := v_res || ('SETUP ERROR ' || sqlstate || ': ' || sqlerrm);
  end;

  return query select unnest(v_res);
end;
$$;

select * from pg_temp.run_db_tests();

-- ---------------------------------------------------------------------------
-- EXPECTED RESULT SUMMARY
--   Every line ends in PASS. Any FAIL or "SETUP ERROR" = stop and fix before
--   Member 2 connects the backend.
--   "SETUP ERROR 23502 ... null value in column" on auth.users: your Supabase
--   version requires extra auth.users columns; add them to the 3-row INSERT
--   in the setup block (e.g. instance_id, aud, role) and re-run.
-- ---------------------------------------------------------------------------
