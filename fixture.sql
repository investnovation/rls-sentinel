-- Mimic a real Supabase project, including the auth shims RLS policies depend on.
create schema if not exists auth;

create or replace function auth.uid() returns uuid
language sql stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid
$$;

do $$ begin
  create role anon nologin;
exception when duplicate_object then null; end $$;

do $$ begin
  create role authenticated nologin;
exception when duplicate_object then null; end $$;

grant usage on schema public, auth to anon, authenticated;
grant execute on function auth.uid() to anon, authenticated;

drop table if exists public.documents, public.notes, public.audit_log, public.invoices cascade;

-- 1. CORRECT: RLS on, policy actually scopes to the owner
create table public.documents (id bigserial primary key, owner_id uuid, body text);
alter table public.documents enable row level security;
create policy doc_sel on public.documents for select using (owner_id = auth.uid());

-- 2. LEAK: RLS on, policy EXISTS but is using(true) -- passes any policy-count check
create table public.notes (id bigserial primary key, owner_id uuid, body text);
alter table public.notes enable row level security;
create policy note_sel on public.notes for select using (true);

-- 3. LEAK: RLS disabled entirely
create table public.audit_log (id bigserial primary key, owner_id uuid, body text);

-- 4. WRITE LEAK: reads correctly scoped, but UPDATE is wide open. Almost nobody tests this.
create table public.invoices (id bigserial primary key, owner_id uuid, total int);
alter table public.invoices enable row level security;
create policy inv_sel on public.invoices for select using (owner_id = auth.uid());
create policy inv_upd on public.invoices for update using (true);

grant select, insert, update, delete on all tables in schema public to anon, authenticated;
grant usage, select on all sequences in schema public to anon, authenticated;

-- Mimic Supabase's auth.users and a table whose owner column FKs to it.
-- This is the shape of almost every real project, and it breaks naive seeding.
create table if not exists auth.users (
  id uuid primary key,
  email text
);

drop table if exists public.posts cascade;
create table public.posts (
  id bigserial primary key,
  user_id uuid references auth.users(id),
  body text
);
alter table public.posts enable row level security;
create policy post_sel on public.posts for select using (user_id = auth.uid());
create policy post_upd on public.posts for update using (true);  -- write leak

grant select, insert, update, delete on all tables in schema public to anon, authenticated;
grant usage, select on all sequences in schema public to anon, authenticated;

-- 5. DELETE LEAK: reads correctly scoped, deletes wide open.
drop table if exists public.receipts cascade;
create table public.receipts (id bigserial primary key, owner_id uuid, amount int);
alter table public.receipts enable row level security;
create policy rec_sel on public.receipts for select using (owner_id = auth.uid());
create policy rec_del on public.receipts for delete using (true);

grant select, insert, update, delete on all tables in schema public to anon, authenticated;
grant usage, select on all sequences in schema public to anon, authenticated;
