-- ============================================================================
--  Investnovation RLS evaluation corpus
--  Jerico Royeth Angeles / investnovation.com
--  Built 16 September 2026. Verified against PostgreSQL 16.13.
--
--  Six tables. Four carry a deliberate, known flaw. Two are controls.
--  Load this into a scratch database, then point any analysis tool at it
--  and compare what it reports against corpus-answers.md.
--
--  Every flaw here was independently verified by execution before this file
--  was written. Nothing in it is derived from any third-party tool.
-- ============================================================================

drop schema if exists public cascade;
create schema public;

do $$ begin
  if not exists (select 1 from pg_roles where rolname='anon')
    then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname='authenticated')
    then create role authenticated nologin; end if;
end $$;
grant usage on schema public to anon, authenticated;

create schema if not exists auth;
grant usage on schema auth to anon, authenticated;   -- Supabase grants this
create or replace function auth.uid() returns uuid language sql stable as
  $$ select nullif(current_setting('request.jwt.claims', true)::json->>'sub','')::uuid $$;

-- Two synthetic tenants used throughout.
--   tenant A  11111111-1111-1111-1111-111111111111
--   tenant B  22222222-2222-2222-2222-222222222222

-- ---------------------------------------------------------------------------
-- 1. invoices   FLAW: blind cross-tenant write.
--    SELECT is correctly scoped. UPDATE says using (true).
--    "update invoices set total = 0" as tenant A rewrites tenant B's rows.
-- ---------------------------------------------------------------------------
create table public.invoices (
  id         uuid primary key default gen_random_uuid(),
  owner_id   uuid not null default '11111111-1111-1111-1111-111111111111',
  customer   text not null default 'unnamed',
  total      numeric not null default 0,
  memo       text
);
alter table public.invoices enable row level security;
create policy inv_sel on public.invoices for select to authenticated using (owner_id = auth.uid());
create policy inv_upd on public.invoices for update to authenticated using (true);
grant select, update on public.invoices to authenticated;
insert into public.invoices (owner_id, customer, total) values
  ('11111111-1111-1111-1111-111111111111','Ada Ltd',   1200),
  ('22222222-2222-2222-2222-222222222222','Lin Corp', 98000);

-- ---------------------------------------------------------------------------
-- 2. profiles   FLAW: column-grant privilege escalation.
--    Policies are correct on both axes, including with check.
--    But UPDATE is granted table-wide, so a user rewrites their own role.
-- ---------------------------------------------------------------------------
create table public.profiles (
  id            uuid primary key,
  email         text not null default 'user@example.com',
  display_name  text,
  plan          text not null default 'free',
  role          text not null default 'user',
  credits       integer not null default 100
);
alter table public.profiles enable row level security;
create policy prof_sel on public.profiles for select to authenticated using (id = auth.uid());
create policy prof_upd on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
grant select, update on public.profiles to authenticated;   -- the flaw
insert into public.profiles (id, email, role) values
  ('11111111-1111-1111-1111-111111111111','ada@example.com','user'),
  ('22222222-2222-2222-2222-222222222222','lin@example.com','user');

-- ---------------------------------------------------------------------------
-- 3. ledger + ledger_summary   FLAW: view bypasses RLS.
--    Base table is correct. The view runs as its owner because
--    security_invoker did not exist before Postgres 15, so it returns
--    every row to anyone who can select from it.
-- ---------------------------------------------------------------------------
create table public.ledger (
  id        uuid primary key default gen_random_uuid(),
  owner_id  uuid not null default '11111111-1111-1111-1111-111111111111',
  entry     text not null default '',
  amount    numeric not null default 0
);
alter table public.ledger enable row level security;
create policy led_sel on public.ledger for select to authenticated using (owner_id = auth.uid());
grant select on public.ledger to authenticated;
insert into public.ledger (owner_id, entry, amount) values
  ('11111111-1111-1111-1111-111111111111','ada opening',  500),
  ('22222222-2222-2222-2222-222222222222','lin opening', 75000);

create view public.ledger_summary as               -- the flaw: no security_invoker
  select entry, amount from public.ledger;
grant select on public.ledger_summary to authenticated;

-- ---------------------------------------------------------------------------
-- 4. admin_set_role()   FLAW: SECURITY DEFINER reachable by default.
--    Nobody granted anything. Postgres grants EXECUTE to PUBLIC at creation,
--    so anon can call it even though anon has no privilege on profiles.
--    search_path is not pinned.
-- ---------------------------------------------------------------------------
create function public.admin_set_role(target uuid, r text) returns void
  language sql security definer as $$
    update public.profiles set role = r where id = target $$;

-- ---------------------------------------------------------------------------
-- 5. documents   CONTROL: correct. Flagging this is a false positive.
--    Scoped on both axes, writes narrowed to columns, anon has nothing.
-- ---------------------------------------------------------------------------
create table public.documents (
  id        uuid primary key default gen_random_uuid(),
  owner_id  uuid not null default '11111111-1111-1111-1111-111111111111',
  title     text not null default 'untitled',
  body      text
);
alter table public.documents enable row level security;
create policy doc_sel on public.documents for select to authenticated using (owner_id = auth.uid());
create policy doc_upd on public.documents for update to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());
grant select on public.documents to authenticated;
grant update (title, body) on public.documents to authenticated;
insert into public.documents (owner_id, title) values
  ('11111111-1111-1111-1111-111111111111','ada notes'),
  ('22222222-2222-2222-2222-222222222222','lin notes');

-- ---------------------------------------------------------------------------
-- 6. app_settings   CONTROL: no tenant column at all.
--    A reference table. There is nothing to isolate. A tool should say so
--    rather than report it clean or report it broken.
-- ---------------------------------------------------------------------------
create table public.app_settings (
  key    text primary key,
  value  text not null default ''
);
alter table public.app_settings enable row level security;
create policy set_sel on public.app_settings for select to authenticated using (true);
grant select on public.app_settings to authenticated;
insert into public.app_settings values ('theme','dark'), ('locale','en-PH');

-- ============================================================================
--  PART TWO: routines and a trigger.
--  Added 16 September 2026, same session, before any third-party tool was run.
--
--  Part one exercises isolation. This part exercises what a test generator
--  should find inside function bodies and trigger behaviour. Six objects:
--  four planted flaws, one control, one cross-tenant definer write.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 7. tier_for_balance()   FLAW: off-by-one on a boundary.
--    Intended: <1000 basic, 1000-9999 plus, >=10000 premium.
--    Written with > 1000, so exactly 1000 falls through and returns 'basic'.
--    One branch, one wrong comparison. A boundary test should catch it.
-- ---------------------------------------------------------------------------
create or replace function public.tier_for_balance(bal numeric) returns text
language plpgsql immutable as $$
begin
  if bal >= 10000 then
    return 'premium';
  elsif bal > 1000 then          -- should be >= 1000
    return 'plus';
  else
    return 'basic';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 8. apply_discount()   FLAW: unreachable branch.
--    pct is only ever 0, 25 or 50, so "if pct > 100" can never run.
--    The docs describe a D chip for suspected dead code. This is the test.
-- ---------------------------------------------------------------------------
create or replace function public.apply_discount(amount numeric, code text)
returns numeric language plpgsql immutable as $$
declare pct numeric := 0;
begin
  if code = 'HALF' then
    pct := 50;
  elsif code = 'QUARTER' then
    pct := 25;
  else
    pct := 0;
  end if;

  if pct > 100 then              -- DEAD: pct is never above 50
    return 0;
  end if;

  return amount - (amount * pct / 100);
end $$;

-- ---------------------------------------------------------------------------
-- 9. charge_account()   FLAW: PII in an exception message.
--    The insufficient-funds path puts the account holder's email address
--    into the RAISE. This is precisely what --pii claims to audit.
-- ---------------------------------------------------------------------------
create or replace function public.charge_account(uid uuid, amt integer)
returns void language plpgsql as $$
declare bal integer; em text;
begin
  select credits, email into bal, em from public.profiles where id = uid;

  if bal is null then
    raise exception 'no profile for %', uid;
  end if;

  if bal < amt then
    raise exception 'insufficient credits for % (balance %)', em, bal;  -- leaks email
  end if;

  update public.profiles set credits = credits - amt where id = uid;
end $$;

-- ---------------------------------------------------------------------------
-- 10. audit_profile_changes   FLAW: trigger is attached to DELETE but
--     returns before writing, so deletions leave no audit trail at all.
--     The trigger looks correct in the catalog. Only firing it reveals this.
-- ---------------------------------------------------------------------------
create table if not exists public.audit_log (
  id      bigserial primary key,
  action  text not null,
  detail  text not null,
  at      timestamptz not null default now()
);

create or replace function public.trg_audit_profile() returns trigger
language plpgsql as $$
begin
  if TG_OP = 'DELETE' then
    return OLD;                  -- BUG: silently writes nothing on delete
  end if;

  insert into public.audit_log(action, detail)
    values (TG_OP, 'profile ' || NEW.id::text);
  return NEW;
end $$;

drop trigger if exists audit_profile_changes on public.profiles;
create trigger audit_profile_changes
  after update or delete on public.profiles
  for each row execute function public.trg_audit_profile();

-- ---------------------------------------------------------------------------
-- 11. transfer_credits()   FLAW: cross-tenant write through a definer.
--     No identity check of any kind. SECURITY DEFINER, so RLS is never
--     evaluated, and EXECUTE is PUBLIC by default. Any caller moves credits
--     between any two accounts.
-- ---------------------------------------------------------------------------
create or replace function public.transfer_credits(from_id uuid, to_id uuid, amt integer)
returns void language plpgsql security definer as $$
begin
  update public.profiles set credits = credits - amt where id = from_id;
  update public.profiles set credits = credits + amt where id = to_id;
end $$;

-- ---------------------------------------------------------------------------
-- 12. describe_plan()   CONTROL: correct on every branch.
--     Total over its input domain, no side effects, no PII, nothing dead.
--     Anything reported against this is a false positive.
-- ---------------------------------------------------------------------------
create or replace function public.describe_plan(p text) returns text
language plpgsql immutable as $$
begin
  if p = 'free' then
    return 'Free plan';
  elsif p = 'pro' then
    return 'Pro plan';
  elsif p = 'enterprise' then
    return 'Enterprise plan';
  else
    return 'Unknown plan';
  end if;
end $$;
