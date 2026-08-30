# RLS Sentinel

**Prove tenant A cannot read or write tenant B's rows. On every deploy.**

Reading `pg_policies` tells you a policy *exists*. It does not tell you the
policy *works*. `using (true)` is a policy. It counts. It isolates nothing.

RLS Sentinel doesn't read your policies. It seeds real rows owned by two
synthetic tenants, assumes each tenant's identity for real, and tries to reach
the other one's data — reads and writes both. Then it rolls everything back.

```
  RLS Sentinel — cross-tenant isolation proof
  7 tables in schema "public"

  LEAK   public.audit_log      anon-read cross-read cross-write cross-delete
         Tenant A DELETED tenant B rows. Any user can empty this table.
  LEAK   public.invoices       cross-write
         Tenant A MODIFIED tenant B rows. Write isolation is broken.
  LEAK   public.notes          anon-read cross-read
         Unauthenticated caller read rows. The anon key ships in your client bundle.
  LEAK   public.receipts       cross-delete
         Tenant A DELETED tenant B rows. Any user can empty this table.
   OK    public.documents

  4 table(s) leaked across tenants.
  These were proven with real seeded rows, not inferred from policy text.
```

## The case for this existing

Look at `public.invoices` above. Read leak: no. Anon leak: no. RLS enabled,
two policies, a completely correct `SELECT` policy scoped to `auth.uid()`.

A linter can grep for a literal `using (true)`, and some do. That catches the
obvious spelling and misses everything shaped like it: a predicate that
resolves to true through a join that always matches, a `USING` clause that is
correct while `WITH CHECK` is absent, a subquery that never actually
constrains. This tool does not read the policy, so it does not care how the
permissiveness is spelled.

It isn't. Its `UPDATE` policy is `using (true)`, and any authenticated user can
silently modify every other tenant's invoices.

## Why write and delete leaks get missed

The obvious way to test a write is to target one:

```sql
update invoices set total = 0 where owner_id = '<other-tenant>';
```

That reads `owner_id` in the `WHERE` clause, so Postgres applies the `SELECT`
policy too. A correct `SELECT` policy hides the row, nothing matches, and the
table looks fine. **It was never actually tested.**

The write that works is blind:

```sql
update invoices set total = 0;
```

No `WHERE`. Constant value. Reads no columns, so the `SELECT` policy never
engages. Only the `UPDATE` policy applies — and if that's `using (true)`, every
row in the table belongs to the attacker.

RLS Sentinel issues the blind write and detects which rows were actually
touched via `ctid`, the physical row version. That works regardless of column
type, and unlike `xmin` it stays valid inside a single transaction.

`DELETE` has the identical flaw and a worse consequence. `delete from t where
owner_id = '<other-tenant>'` is blocked by a correct `SELECT` policy. `delete
from t` is not — and a `DELETE` policy of `using (true)` means any authenticated
user can empty the table. `public.receipts` above is exactly that: reads
perfectly scoped, deletes wide open.

The delete probe is skipped on tables above 10,000 estimated rows. A blind
`DELETE` is expensive even when rolled back, and locking up a large table to
prove a point is not a trade worth making.

## Ownership through a join

Most real schemas have tables that own nothing themselves. A `messages` table
has a `conversation_id` and no `user_id` — the *conversation* is what belongs to
someone. These are usually the tables holding the content that actually matters,
and a tool that only looks for `user_id` skips every one of them.

RLS Sentinel follows the foreign key. It seeds a parent row for each tenant,
links a child row to each, and probes through the relationship:

```
  LEAK   public.messages    cross-delete
         conversation_id -> conversations.user_id
```

Read isolation held there — the `exists (select 1 from conversations ...)`
policy does its job. The `DELETE` policy was `using (true)`, so any authenticated
user could empty the table. Reads correct, deletes wide open, and nothing that
inspects policy metadata would have caught it.

Three ownership shapes are handled: a direct column, a primary key that is
itself the user id (Supabase's profile pattern), and a foreign key to a table
that has one. Foreign key chains are seeded to their root, so
`memory -> profiles -> auth.users` works.

## Usage

No install required:

```bash
npx rls-sentinel --db "$DATABASE_URL"
npx rls-sentinel --db "$DATABASE_URL" --schema public --json
```

Or install it globally:

```bash
npm i -g rls-sentinel
rls-sentinel --db "$DATABASE_URL"
```

<details>
<summary>From source</summary>

```bash
git clone https://github.com/investnovation/rls-sentinel
cd rls-sentinel
npm install
npx tsx src/index.ts --db "$DATABASE_URL"
```

</details>

Flags: `--schema` (default `public`), `--json` for machine-readable output,
`--insecure` to skip TLS certificate verification, `--allow-production` to
override the guard.

Exit codes: `0` clean, `1` leaks found, `2` error, `3` refused (see Safety). The non-zero exit is the
entire point — this is a CI gate, not a report you read once.

### As a GitHub Action

This is the point of the tool. A one-time scan tells you the isolation held
when you ran it. A CI gate tells you it still holds after the pull request that
added a table on Thursday.

```yaml
# .github/workflows/rls.yml
name: rls
on: [pull_request]

jobs:
  isolation:
    runs-on: ubuntu-latest
    steps:
      - uses: investnovation/rls-sentinel@v0.7.0
        with:
          database-url: ${{ secrets.SUPABASE_BRANCH_DB_URL }}
```

Point it at a preview branch or staging database. The production guard will
refuse a live one, which is the intended behaviour in CI.

## Safety

Every probe runs inside a transaction that is always rolled back, with a
savepoint per table. Nothing is committed. No row is left behind. Tables that
can't be seeded (NOT NULL columns without defaults, FK constraints) are reported
as `SKIP` with the reason — never silently passed.

### The production guard

Rollback covers the data. It does not cover everything, so the tool refuses to
run against a database that looks live:

```
  Refusing to run: this looks like a live database.
    - auth.users contains 40 accounts.
    - Tables carrying substantial data: notes (~5000).

  This tool inserts rows and runs updates. It rolls all of it back,
  but rollback does not undo everything:
    - Sequence values are consumed permanently (5 table(s) affected).
    - Triggers fire before rollback: invoices.
      Anything one of them sends over the network has already left.
    - Row locks are held for the duration of the probe.
```

Three things survive a rollback:

- **Sequences are non-transactional.** Inserting into a table with a `bigserial`
  primary key permanently consumes id values. Cosmetic alone; alarming if
  someone is watching for gaps.
- **Triggers fire before the rollback.** One that writes to an audit table is
  rolled back with everything else. One that calls out over the network —
  `pg_net`, a webhook, an email, a queue in another system — has already sent it.
- **Row locks are held** for the duration of the probe.

Detection uses the number of accounts in `auth.users`, planner row estimates, and
the connection string. Override with `--allow-production` once you've read the
warning.

Exit `3` means refused.

Point it at a branch or staging database.

## What this tool cannot prove

An attack-based tool only tries the situations it sets up. That is its honest
limit, and pretending otherwise would make it dangerous.

```sql
create policy p on org_docs for select
  using (owner_id = auth.uid() or org_id is not null);
```

Two branches. The probe seeds rows differing only by `owner_id`, so `org_id`
stays NULL, the second branch never fires, and an earlier version of this tool
reported **OK** — on a table that in production hands every row to every
authenticated user. A confident green on a wide-open table is the worst output
this tool could produce.

It can't execute every branch — that's constraint solving over arbitrary SQL —
but it can know when it hasn't. Postgres records what each policy depends on in
`pg_depend`: every column and every table the expression touches, structurally,
no parsing. Compare that against what the probe varied, and anything left over
is a branch nobody reached:

```
UNPROVEN public.org_docs
         Policies also depend on column(s) org_id and table(s) public.org_members,
         which the probe never varied. Untested branch.
```

`UNPROVEN` is not `OK`. It means no leak was found *and* the result doesn't
cover the whole policy. It doesn't fail the build by default — a gate that fires
on every org-scoped policy gets switched off within a week — but `--strict`
makes it fail for teams that want that.

The eventual answer is to parse the policy, enumerate its cases, and generate
rows that make each one pass and fail, then execute those. Static analysis
builds the test matrix; execution is the oracle. Neither alone is enough.

Credit: raised by u/pgsql-dev2 on r/Supabase.

## Column privileges (advisory)

RLS answers *which rows*. Column grants answer *which columns of those rows*.
They are different axes, and a correct policy does nothing about the second.

A table with `using (user_id = auth.uid())` **and** `with check (user_id =
auth.uid())` is perfectly isolated — and a user can still rewrite every column
of a row that genuinely is theirs, including their balance, their plan, their
role, or their item count. `WITH CHECK` doesn't help: changing `count` never
violates `user_id = auth.uid()`.

```
update inventory set count = 999999 where user_id = auth.uid();
-- UPDATE 1. Policy satisfied. Count is now 999999.
```

The fix is column-level grants:

```sql
revoke update on public.inventory from authenticated;
grant  update (item_id) on public.inventory to authenticated;
-- ERROR: permission denied for table inventory
```

This is reported as an **advisory** and never changes the exit code. Supabase
grants table-wide privileges to `authenticated` by default, so failing CI on it
would fail on essentially every project on day one — and a gate that always
fails gets switched off. The tool *proves* leaks; this *observes* a risk. Those
belong in separate lists.

Credit: raised by u/guidondor on r/Supabase.

## Testing itself

A tool that proves other people's isolation should prove its own.

```bash
DATABASE_URL=postgresql://... node ./test/selftest.mjs
```

It loads both fixtures into a real Postgres, runs the CLI, and asserts every
expected finding — including the negative ones. A false positive on a correctly
secured table is worse than a miss, because it ships noise into someone's CI and
teaches them to ignore the gate. Those assertions are the ones that matter.

Runs on every push against Postgres 16. `real-fixture.sql` is modelled on an
actual production schema rather than an invented one.

## Status

v0.4.0. Four leak classes — unauthenticated read via the anon key, cross-tenant
read, cross-tenant blind write, cross-tenant blind delete — across three
ownership shapes: direct column, primary-key-as-user-id, and single-hop foreign
key join.

Not yet covered: `SECURITY DEFINER` functions that bypass RLS, storage bucket
policies, `INSERT` probes (forging rows owned by another tenant), composite
ownership, and multi-hop join ownership (a table two or more foreign keys away
from anything owned).

## Who made this

Built by [Investnovation](https://investnovation.com) while hardening a
production Supabase app. The bug that started it — a user id trusted from a
request body instead of the verified session — is written up
[here](https://investnovation.com/blog/hardening-ai-chat-api), including the
part where a service-role client and a client-supplied id each removed the
other's protection.

Issues and pull requests welcome. If you found something this tool missed, that
is the most useful thing you can send.

If you want a pair of eyes on a Supabase project beyond what this covers —
`SECURITY DEFINER` functions, storage buckets, service-role key handling, auth
configuration — that is work I take on. Details and pricing at
[investnovation.com/supabase-security-audit](https://investnovation.com/supabase-security-audit).
