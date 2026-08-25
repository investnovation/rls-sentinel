-- Fixture modelled on a real Supabase schema, not an invented one.
drop table if exists public.messages, public.conversations, public.memory,
  public.crisis_interventions, public.rate_limits, public.waitlist,
  public.profiles cascade;

-- profiles.id IS the user id (ownership by primary key)
create table public.profiles (
  id uuid primary key references auth.users(id),
  display_name text
);
alter table public.profiles enable row level security;
create policy prof_sel on public.profiles for select using (id = auth.uid());

-- two-level FK chain: conversations -> profiles -> auth.users
create table public.conversations (
  id bigserial primary key,
  user_id uuid references public.profiles(id),
  title text
);
alter table public.conversations enable row level security;
create policy conv_sel on public.conversations for select using (user_id = auth.uid());

create table public.memory (
  id bigserial primary key,
  user_id uuid references public.profiles(id),
  fact text
);
alter table public.memory enable row level security;
create policy mem_sel on public.memory for select using (user_id = auth.uid());

-- join-resolved ownership: messages belongs to a user via conversations
create table public.messages (
  id bigserial primary key,
  conversation_id bigint references public.conversations(id),
  body text
);
alter table public.messages enable row level security;
create policy msg_sel on public.messages for select using (
  exists (select 1 from public.conversations c
           where c.id = messages.conversation_id and c.user_id = auth.uid())
);
-- deliberately wide-open delete, to see if we can ever reach it
create policy msg_del on public.messages for delete using (true);

-- server-only tables: RLS on, zero policies
create table public.rate_limits (id bigserial primary key, identifier text, n int);
alter table public.rate_limits enable row level security;

grant select, insert, update, delete on all tables in schema public to anon, authenticated;
grant usage, select on all sequences in schema public to anon, authenticated;
