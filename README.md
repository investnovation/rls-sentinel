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

Every scanner that reads policy metadata calls that table safe.

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

```bash
npx rls-sentinel --db "$DATABASE_URL"
npx rls-sentinel --db "$DATABASE_URL" --schema public --json
```

Exit codes: `0` clean, `1` leaks found, `2` error, `3` refused (see Safety). The non-zero exit is the
entire point — this is a CI gate, not a report you read once.

```yaml
# .github/workflows/rls.yml
- run: npx rls-sentinel --db ${{ secrets.SUPABASE_DB_URL }}
```

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

## Status

v0.4.0. Four leak classes — unauthenticated read via the anon key, cross-tenant
read, cross-tenant blind write, cross-tenant blind delete — across three
ownership shapes: direct column, primary-key-as-user-id, and single-hop foreign
key join.

Not yet covered: `SECURITY DEFINER` functions that bypass RLS, storage bucket
policies, `INSERT` probes (forging rows owned by another tenant), composite
ownership, and multi-hop join ownership (a table two or more foreign keys away
from anything owned).
