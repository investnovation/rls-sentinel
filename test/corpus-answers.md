# The corpus, answered

Twelve objects in [`corpus.sql`](./corpus.sql). **Nine carry a known flaw.
Three are controls:** 5 and 12 are correct, 6 is unprovable.

Every result below is real output, produced by execution on PostgreSQL 16.13 on
16 September 2026 before any third-party tool was run against the schema.
Object 1 was re-verified on PostgreSQL 18.6 on 17 September 2026 and reproduces
unchanged.

Keep this file off the screen while a tool runs. Score afterwards.

Part one (1-6) is tables, a view and isolation. Part two (7-12) is routines and
a trigger.

---

## 1. `invoices` — blind cross-tenant write

`SELECT` is correctly scoped to `owner_id = auth.uid()`. `UPDATE` says
`using (true)`. A write with no `WHERE` reads no column, so the SELECT policy
never engages and only the UPDATE policy applies.

```
as tenant A:  select count(*) from invoices    ->  1        (her own row)
              update invoices set total = 0    ->  UPDATE 2 (both tenants)

 customer | total
----------+-------
 Ada Ltd  |     0
 Lin Corp |     0          <- tenant B's invoice, zeroed by tenant A
```

**A correct tool reports:** cross-tenant write isolation is broken on `invoices`.

**A miss here is the most serious possible miss.** This is the flaw the whole
category exists to catch, and the obvious test (`where owner_id = '<other>'`)
cannot find it.

---

## 2. `profiles` — column-grant privilege escalation

Both policies are correct, `with check` is present, and the row still belongs to
the same user before and after. The flaw is not in the policy at all. `UPDATE`
was granted table-wide, so every column is writable.

```
as tenant A:  update profiles set role='admin', credits=999999 where id = auth.uid();
              ->  UPDATE 1

      email      | role  | credits
-----------------+-------+---------
 ada@example.com | admin |  999999
```

**A correct tool reports:** `authenticated` holds table-wide UPDATE on
`profiles`, so `role`, `plan` and `credits` are user-writable.

**Fix:**

```sql
revoke update on profiles from authenticated;
grant  update (email, display_name) on profiles to authenticated;
```

A tool that only reads policies will call this table clean. It is not. RLS
decides which rows. GRANT decides which columns. They are separate axes and a
correct answer on one says nothing about the other.

---

## 3. `ledger_summary` — view bypasses RLS on its base table

`ledger` is correct. The view has no `security_invoker`, so it runs as its
owner. `security_invoker` did not exist before PostgreSQL 15, so most views in
most projects were written without it.

```
as tenant A:
    src     | count
------------+-------
 base table |     1
 via view   |     2     <- every tenant's rows
```

**A correct tool reports:** `public.ledger_summary` bypasses RLS on
`public.ledger`.

**Fix:** `alter view public.ledger_summary set (security_invoker = true);`

Note that a proof run against `ledger` itself passes, and is right to. The leak
is in a different object, which is what makes this one easy to miss with a
table-by-table sweep.

---

## 4. `admin_set_role()` — SECURITY DEFINER reachable by default

Nobody granted anything. PostgreSQL grants `EXECUTE` to `PUBLIC` at creation, so
`anon` can call it despite holding no privilege on `profiles`. `search_path` is
not pinned.

```
as anon:  select public.admin_set_role('2222...','admin');

      email      | role
-----------------+-------
 ada@example.com | user
 lin@example.com | admin    <- promoted by an unauthenticated caller
```

**A correct tool reports:** the function is reachable by a client role and runs
as its owner. Whether calling it is harmful depends on the body, so "reachable"
is the honest verdict rather than "vulnerable".

**Fix:** `revoke execute on function public.admin_set_role(uuid, text) from public;`

---

## 5. `documents` — CONTROL, correct

Scoped on both axes, writes narrowed to `(title, body)`, `anon` holds nothing.

```
as tenant A:  update documents set owner_id = '<tenant B>';
              ->  ERROR: permission denied for table documents
              update documents set title='renamed' where owner_id = auth.uid();
              ->  UPDATE 1
```

Escalation blocked, legitimate write untouched.

**Flagging this table is a false positive.** How a tool behaves here matters as
much as what it finds, because a checker that cries wolf on correct tables gets
deleted within a week.

---

## 6. `app_settings` — CONTROL, nothing to isolate

A reference table with no tenant column. Readable by every authenticated user
on purpose.

**A correct tool says it cannot prove isolation here, and explains why.**
Reporting it clean overstates. Reporting it broken is wrong. This is the case
that separates a tool with an honest vocabulary from one without, and it is the
hardest of the twelve to get right.

---

# Part two: routines and a trigger

## 7. `tier_for_balance()` — off-by-one on a boundary

Written `> 1000` where it should be `>= 1000`.

```
  bal  |   got   | intended
-------+---------+----------
   999 | basic   | basic
  1000 | basic   | plus      <- the only wrong answer
  1001 | plus    | plus
  9999 | plus    | plus
 10000 | premium | premium
```

Every branch is reachable and every branch runs. Coverage will read 100%.

**The bug is invisible to coverage and only a boundary test finds it.** A tool
that reports perfect branch coverage here and says nothing else is correct and
also telling you nothing.

There is a sharper trap underneath. A generator that derives the boundary value
from the condition will test exactly `bal = 1000`, which is the single most
revealing input in the function, and then assert whatever the code returns. The
off-by-one is not merely missed; it is pinned by a passing test that will go
green forever. A test generated from an implementation can only assert what the
code does, never what it was meant to do.

## 8. `apply_discount()` — unreachable branch

`pct` is only ever 0, 25 or 50, so `if pct > 100` can never execute.

```
  code   | result
---------+---------
 HALF    | 100      (50% off 200)
 QUARTER | 150
 NONE    | 200
 (null)  | 200
```

No input reaches the dead branch.

**A correct tool marks it dead rather than merely uncovered**, and points at the
logic that computes `pct` rather than at the dead line itself.

## 9. `charge_account()` — PII in an exception message

```
MESSAGE >>> insufficient credits for ada@example.com (balance 100)
```

An email address in a `RAISE`. The happy path never leaks; only the
insufficient-funds path does, so **the error path has to actually be driven.**
Reading the source finds the string. Proving it reaches a caller does not
happen without invoking the handler.

## 10. `audit_profile_changes` — trigger writes nothing on DELETE

Attached to `after update or delete`, but the body returns early on DELETE.

```
one UPDATE and one DELETE produced:

 action |                  detail
--------+----------------------------------------------
 UPDATE | profile 1111...

 audit_rows_total: 1
```

The catalog says the trigger covers DELETE. **Only firing it reveals that
deletions are silently unaudited.** A tool that reads definitions cannot find
this. A tool that fires the DML and asserts the write footprint should, but only
if it enumerates the events the trigger is declared for rather than driving one
event twice.

Note that `authenticated` holds no DELETE grant on `profiles`, so a
client-reachability pass is right to report DELETE as undrivable for that role.
The trigger's own behaviour is still testable as the owner. Those are two
different questions and a good report answers both separately.

## 11. `transfer_credits()` — cross-tenant write through a definer

No identity check of any kind. `SECURITY DEFINER`, so RLS never applies, and
`EXECUTE` is `PUBLIC` by default.

```
before, as anon:  ada 100   lin 100
  select public.transfer_credits(ada, lin, 90);
after:            ada  10   lin 190
```

An unauthenticated caller moved credits between two accounts.

**A security pass should name both the function and the table its write
reaches.** And if the write channel cannot be probed, it should say so. An
unproven write channel reported as enforced is worse than no report at all.

## 12. `describe_plan()` — CONTROL, correct

Four branches, all correct, total over its input domain, no side effects, no
PII, nothing dead.

**Anything reported here is a false positive.**

---

## Scorecard

| | Found | Notes |
|---|---|---|
| 1. blind cross-tenant write | | the one that matters most |
| 2. column-grant escalation | | policies are correct; grants are not |
| 3. view bypass | | `ledger` itself passes and should |
| 4. definer reachable by anon | | "reachable" beats "vulnerable" |
| 5. `documents` | | must be silent |
| 6. `app_settings` | | must say unprovable |
| 7. boundary off-by-one | | coverage reads 100% regardless |
| 8. dead branch | | dead, not merely uncovered |
| 9. PII in RAISE | | needs the error path driven |
| 10. trigger silent on DELETE | | needs the DML fired, per declared event |
| 11. cross-tenant definer write | | should name the table reached |
| 12. `describe_plan` | | must be silent |

Nine flaws, three controls.

The count is the least interesting output. What to look at is the wording on 5,
6 and 12, and whether anything the tool could not prove was reported as
unproven rather than rounded up to a pass. Anyone can find a leak in a schema
built to leak. What separates a tool worth paying for is whether it stays quiet
on the correct object, admits what it could not establish on the unprovable one,
and refuses to let an uncertainty disappear into a summary line.

---

*Corrected 18 September 2026. An earlier private version of this file said
"eight flaws, four controls", which was part one's split (four flaws, two
controls) carried forward after part two added five flaws and one control.*
