-- ============================================================================
-- BeEvolve  |  02_beevolve_alter_existing.sql
-- Run ONLY AFTER 01_beevolve_create.sql, and ONLY because the live database
-- already has public.profiles (from supabase/schema.sql) and auth.users rows.
-- Do NOT recreate existing tables. Nothing here drops data.
-- ============================================================================

-- A. Copy every existing account into public.users (profiles -> users).
--    Run only if public.profiles exists (it does if supabase/schema.sql was run).
insert into public.users (id, email, full_name, mobile, email_verified, created_date)
select au.id,
       au.email,
       coalesce(p.full_name, au.raw_user_meta_data->>'full_name', ''),
       coalesce(p.mobile,    au.raw_user_meta_data->>'mobile'),
       (au.email_confirmed_at is not null),
       coalesce(p.created_at, au.created_at)
  from auth.users au
  left join public.profiles p on p.id = au.id
  where au.email is not null
on conflict (id) do nothing;

-- B. Make the first admin. Replace the literal with the real admin email, then run.
update public.users
   set role = 'admin'
 where email = 'pdtmgrp@gmail.com'::extensions.citext;

-- C. Link existing mst_plan rows to Razorpay plans (only after the Razorpay plan exists).
--    Run per plan once Member 2 creates it in Razorpay (see plan, Razorpay section).
--    Example for the monthly premium plan; replace plan_xxx with the real id:
-- (executed as a normal statement by whoever creates the plan)
-- update public.mst_plan set provider_plan_id = 'plan_xxx'
--  where product_id = (select id from public.mst_product where slug = 'beevolve-premium');

-- D. If a table named email_otps exists in the live DB (the backend uses it but
--    supabase/schema.sql never created it): it is replaced by public.otp_verifications.
--    OTP rows live 5 minutes, so nothing is migrated. Drop it ONLY after Member 2's
--    auth.py release is live (otherwise OTP login breaks):
--      drop table if exists public.email_otps;
--    (kept as a comment on purpose: do not run this before the backend release.)

-- E. Existing profiles table: KEEP until Member 2's release has been live and verified
--    for one day. Then run:
--      drop table if exists public.profiles;
--    and re-run the handle_new_user() function body without the profiles block
--    (section 5.2 of 01_beevolve_create.sql minus the "if to_regclass(...)" block).
--    (kept as a comment on purpose.)

-- F. Existing profiles policies stay as they are until profiles is dropped.
--    No ALTER TABLE on profiles is required.
