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

  LEAK   public.audit_log      anon-read cross-read cross-write
         Tenant A MODIFIED tenant B rows. Write isolation is broken.
  LEAK   public.invoices       cross-write
         Tenant A MODIFIED tenant B rows. Write isolation is broken.
  LEAK   public.notes          anon-read cross-read
         Unauthenticated caller read rows. The anon key ships in your client bundle.
   OK    public.documents

  3 table(s) leaked across tenants.
  These were proven with real seeded rows, not inferred from policy text.
```

## The case for this existing

Look at `public.invoices` above. Read leak: no. Anon leak: no. RLS enabled,
two policies, a completely correct `SELECT` policy scoped to `auth.uid()`.

Every scanner that reads policy metadata calls that table safe.

It isn't. Its `UPDATE` policy is `using (true)`, and any authenticated user can
silently modify every other tenant's invoices.

## Why write leaks get missed

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

## Usage

```bash
npx rls-sentinel --db "$DATABASE_URL"
npx rls-sentinel --db "$DATABASE_URL" --schema public --json
```

Exit codes: `0` clean, `1` leaks found, `2` error. The non-zero exit is the
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

Point it at staging, not production, until you trust it.

## Status

v0.1.0. Detects three leak classes: unauthenticated read via the anon key,
cross-tenant read, cross-tenant blind write.

Not yet covered: `SECURITY DEFINER` functions that bypass RLS, storage bucket
policies, `DELETE` probes, composite ownership, and tables whose ownership is
resolved through a join rather than a column.
