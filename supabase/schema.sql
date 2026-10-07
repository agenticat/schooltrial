-- ═══════════════════════════════════════════════════════════════════════════════
--  School SaaS — security schema + RLS policies
--  Run this ONCE in the Supabase SQL editor (Dashboard → SQL → New query).
--  It is idempotent: running it twice is safe.
-- ═══════════════════════════════════════════════════════════════════════════════
--
--  WHY THIS FILE EXISTS
--  Until now the three HTML pages talked to PostgREST with the public anon key and
--  no visible policies, which means tenant isolation depended entirely on invisible
--  dashboard settings. This file makes the intended rules explicit:
--
--    * master_panel.html      → only rows listed in platform_admins
--    * admin.html             → a school owner, scoped to their own school_id
--    * xyz_school.html        → may read ONLY the public columns of ONE school
--                               (via the RPC below), and may INSERT inquiries
--
--  ⚠️  STEP 2 REMOVES EXISTING POLICIES ON THESE TABLES (including any wide-open
--      "everyone can read everything" prototype policy). Review it before running.
--      If you want to see what is currently there, run:
--        select tablename, policyname, roles, cmd, qual
--        from pg_policies where schemaname = 'public' order by tablename;
--
--  AFTER RUNNING: sign in to master_panel.html, open the "setup" screen, and insert
--  your own uid into platform_admins (or run STEP 1's insert manually).
-- ═══════════════════════════════════════════════════════════════════════════════


-- ═══ STEP 1 — the platform-admin registry ═════════════════════════════════════
create table if not exists public.platform_admins (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  email      text,
  created_at timestamptz not null default now()
);

alter table public.platform_admins enable row level security;

-- An admin may read only their own row. There is deliberately NO insert/update/delete
-- policy, so nobody can promote themselves through the API — add admins from the SQL
-- editor or with the service-role key.
drop policy if exists "read own admin row" on public.platform_admins;
create policy "read own admin row" on public.platform_admins
  for select to authenticated
  using (user_id = auth.uid());

-- Is the caller a platform admin?  SECURITY DEFINER so the policy can check the
-- registry regardless of the caller's own row-level access.
create or replace function public.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (select 1 from public.platform_admins where user_id = auth.uid());
$$;

-- Does the caller own this school?  Used by every child-table policy.
create or replace function public.owns_school(p_school uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (select 1 from public.schools s where s.id = p_school and s.owner_id = auth.uid());
$$;

revoke execute on function public.is_platform_admin() from anon;
revoke execute on function public.owns_school(uuid) from anon;
grant  execute on function public.is_platform_admin() to authenticated;
grant  execute on function public.owns_school(uuid) to authenticated;

-- Promote your own account (replace the uid with the one shown on the master panel's
-- setup screen, or find it under Authentication → Users):
--
--   insert into public.platform_admins (user_id, email)
--   values ('00000000-0000-0000-0000-000000000000', 'you@example.com')
--   on conflict (user_id) do nothing;


-- ═══ STEP 2 — retire the wide-open prototype policies ═════════════════════════
-- Comment this block out if you would rather remove them by hand.
do $$
declare r record;
begin
  for r in
    select tablename, policyname from pg_policies
    where schemaname = 'public'
      and tablename in (
        'schools','notices','toppers','galleries','facilities','downloads',
        'fee_structures','staff_members','achievements','testimonials','inquiries'
      )
      and policyname not in (
        'platform admin: full access to schools',
        'owner: read own school','owner: update own school',
        'public: read one school by api key',
        'owner: read rows','owner: insert rows','owner: update rows','owner: delete rows',
        'public: submit an inquiry','owner: read inquiries','owner: delete inquiries'
      )
  loop
    execute format('drop policy if exists %I on public.%I', r.policyname, r.tablename);
    raise notice 'dropped policy %.%', r.tablename, r.policyname;
  end loop;
end $$;


-- ═══ STEP 3 — schools: owner-scoped, plus full access for platform admins ═════
alter table public.schools enable row level security;

drop policy if exists "platform admin: full access to schools" on public.schools;
create policy "platform admin: full access to schools" on public.schools
  for all to authenticated
  using (public.is_platform_admin())
  with check (public.is_platform_admin());

drop policy if exists "owner: read own school" on public.schools;
create policy "owner: read own school" on public.schools
  for select to authenticated
  using (owner_id = auth.uid());

drop policy if exists "owner: update own school" on public.schools;
create policy "owner: update own school" on public.schools
  for update to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

-- NOTE: there is no anon policy on public.schools. The public website no longer reads
-- the table directly — it calls the RPC in STEP 4, which exposes only public columns
-- and only for the single school whose api_key was requested. That is what stops
-- `GET /rest/v1/schools?select=*` from dumping every tenant's api_key and owner_id.


-- ═══ STEP 4 — the public lookup RPC ════════════════════════════════════════════
-- Returns the public-facing columns of ONE school, chosen by its public api_key.
-- owner_id / api_key / username are never returned.
create or replace function public.public_school_by_key(p_key text)
returns table (
  id uuid, school_name text, tagline text, about_us_text text,
  logo_url text, banner_image_url text, primary_color text, secondary_color text,
  phone_primary text, phone_secondary text, email_primary text, school_timing text,
  established_year text, affiliation_board text, affiliation_number text,
  admission_status boolean, vision_text text, mission_text text,
  principal_name text, principal_qualification text, principal_photo_url text, principal_message text,
  director_name text, director_qualification text, director_photo_url text, director_message text,
  address text, city text, state text, pincode text,
  facebook_url text, youtube_url text, instagram_url text, google_maps_url text
)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select s.id, s.school_name, s.tagline, s.about_us_text,
         s.logo_url, s.banner_image_url, s.primary_color, s.secondary_color,
         s.phone_primary, s.phone_secondary, s.email_primary, s.school_timing,
         s.established_year, s.affiliation_board, s.affiliation_number,
         s.admission_status, s.vision_text, s.mission_text,
         s.principal_name, s.principal_qualification, s.principal_photo_url, s.principal_message,
         s.director_name, s.director_qualification, s.director_photo_url, s.director_message,
         s.address, s.city, s.state, s.pincode,
         s.facebook_url, s.youtube_url, s.instagram_url, s.google_maps_url
  from public.schools s
  where s.api_key::text = p_key          -- cast: a malformed key can never raise an error
  limit 1;
$$;

grant execute on function public.public_school_by_key(text) to anon, authenticated;

comment on function public.public_school_by_key(text) is
  'Public website lookup: returns the public columns of one school by its api_key.';


-- ═══ STEP 5 — child tables: owners may manage their own rows only ═════════════
do $$
declare
  t text;
  tables text[] := array[
    'notices','toppers','galleries','facilities','downloads',
    'fee_structures','staff_members','achievements','testimonials'
  ];
begin
  foreach t in array tables loop
    if to_regclass('public.' || t) is null then
      raise notice 'skipping public.% (table does not exist)', t;
      continue;
    end if;

    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists "owner: read rows" on public.%I', t);
    execute format('drop policy if exists "owner: insert rows" on public.%I', t);
    execute format('drop policy if exists "owner: update rows" on public.%I', t);
    execute format('drop policy if exists "owner: delete rows" on public.%I', t);

    execute format('create policy "owner: read rows" on public.%I
                      for select to authenticated using (public.owns_school(school_id))', t);
    -- the insert check also pins school_id to a school the caller owns, so a forged
    -- school_id in the request body is rejected
    execute format('create policy "owner: insert rows" on public.%I
                      for insert to authenticated with check (public.owns_school(school_id))', t);
    execute format('create policy "owner: update rows" on public.%I
                      for update to authenticated
                      using (public.owns_school(school_id))
                      with check (public.owns_school(school_id))', t);
    execute format('create policy "owner: delete rows" on public.%I
                      for delete to authenticated using (public.owns_school(school_id))', t);

    -- platform admins keep read access (support / diagnostics)
    execute format('drop policy if exists "platform admin: read rows" on public.%I', t);
    execute format('create policy "platform admin: read rows" on public.%I
                      for select to authenticated using (public.is_platform_admin())', t);
  end loop;
end $$;


-- ═══ STEP 6 — inquiries: anonymous INSERT in, owner-only read out ═════════════
do $$
begin
  if to_regclass('public.inquiries') is null then
    raise notice 'skipping public.inquiries (table does not exist)';
    return;
  end if;

  execute 'alter table public.inquiries enable row level security';

  execute 'drop policy if exists "public: submit an inquiry" on public.inquiries';
  execute 'create policy "public: submit an inquiry" on public.inquiries
             for insert to anon, authenticated with check (true)';

  execute 'drop policy if exists "owner: read inquiries" on public.inquiries';
  execute 'create policy "owner: read inquiries" on public.inquiries
             for select to authenticated using (public.owns_school(school_id))';

  execute 'drop policy if exists "owner: delete inquiries" on public.inquiries';
  execute 'create policy "owner: delete inquiries" on public.inquiries
             for delete to authenticated using (public.owns_school(school_id))';

  -- The public form has no login, so this policy cannot restrict *who* may insert.
  -- It only guarantees that whatever is inserted is bounded in size and shape.
  -- Add a captcha (Turnstile/hCaptcha) or an edge function if you need real abuse control.
  execute 'alter table public.inquiries drop constraint if exists inquiries_public_shape';
  execute $c$alter table public.inquiries add constraint inquiries_public_shape check (
      status = 'new'
      and char_length(coalesce(student_name,    '')) between 1 and 120
      and char_length(coalesce(parent_name,     '')) between 1 and 120
      and char_length(coalesce(phone_number,    '')) between 4 and 20
      and char_length(coalesce(email,           '')) <= 160
      and char_length(coalesce(class_applied_for,'')) <= 60
      and char_length(coalesce(message,         '')) <= 2000
  )$c$;
end $$;


-- ═══ STEP 7 — verify ══════════════════════════════════════════════════════════
-- Still signed in as nobody (anon), this must now fail / return no rows:
--   select * from public.schools;
-- And this must return exactly one school's public columns:
--   select * from public.public_school_by_key('<paste an api_key>');
--
-- Policy inventory:
--   select tablename, policyname, roles, cmd from pg_policies
--   where schemaname = 'public' order by tablename, policyname;
