# The RLS evaluation corpus

A deliberately flawed PostgreSQL schema for testing database security tools.

Twelve numbered objects. **Nine carry a known flaw. Three are controls:** two
are correct and must not be flagged, and one cannot be proven either way and
has to be reported as unprovable.

```
psql -d scratch -f corpus.sql
```

Then point any tool at it and compare against [`corpus-answers.md`](./corpus-answers.md).

## Why the controls are the point

Anyone can find a leak in a schema built to leak. The corpus exists to test the
three things that actually decide whether a security tool is worth running:

**Does it stay quiet on correct code?** Object 5 (`documents`) is scoped on both
axes, with writes narrowed by column grant. Any finding there is a false
positive. A checker that cries wolf on a correct table gets deleted inside a
week, so silence here is a result, not an absence of one.

**Does it admit what it cannot prove?** Object 6 (`app_settings`) is shared
reference data with no tenant column. There is nothing to isolate. "Clean"
overstates, "broken" is wrong, and the only honest answer is that isolation is
not provable here and here is why. A tool without that vocabulary will say
something false.

**Does uncertainty survive the summary?** Several flaws here are invisible to
the obvious test. If a probe cannot run, the report must say so rather than
rounding an unproven check up to a pass. This one is personal: rls-sentinel
shipped a version that printed *no cross-tenant leaks found* after proving
nothing at all. It was found by building this corpus and running the published
tool against it.

## Two traps worth knowing about before you run anything

**A correct SELECT policy hides a broken UPDATE policy.** The obvious test is

```sql
update invoices set total = 0 where owner_id = '<other tenant>';
```

That reads a column, so the SELECT policy applies, the row is hidden, nothing
matches, and the table looks scoped. Drop the `WHERE` and no column is read, so
only the UPDATE policy applies. If it says `using (true)`, every tenant's rows
are now yours. Object 1.

**RLS decides rows. GRANT decides columns.** Object 2 has correct policies on
both axes, including `with check`, and the row belongs to the same user before
and after the write. The flaw is that `UPDATE` was granted table-wide, so the
user can rewrite their own `role` and `credits`. A tool that only reads policies
will call that table clean.

## Provenance

Built 16 September 2026 and committed before any third-party tool was run
against it. Every flaw was verified by execution on PostgreSQL 16.13 before it
was written down; object 1 was re-verified on 18.6 on 17 September 2026. Nothing
in the corpus is derived from any third-party tool.

The corpus needs no Supabase. It creates its own `anon` and `authenticated`
roles and its own `auth.uid()`, resolving from `request.jwt.claims` the way
Supabase does, so it loads into any PostgreSQL 15 or later.

## Notes

`corpus.sql` opens with `drop schema if exists public cascade`, which takes any
extension installed in `public` with it. If your tool needs extensions in that
schema, recreate them after each reload.

MIT, same as the rest of this repository. If you run a tool against this and get
a result worth discussing, or you think one of the twelve is wrong, open an
issue. Corrections are more useful to me than agreement.

The reasoning behind all of this, and the bug in my own tool that made me build
it, is written up at
[investnovation.com/blog/rls-evaluation-corpus](https://investnovation.com/blog/rls-evaluation-corpus).

Jerico Royeth Angeles / [investnovation.com](https://investnovation.com)
