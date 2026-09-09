import type { PoolClient } from 'pg';

/**
 * Column privilege advisory.
 *
 * RLS answers "which rows may I touch". Column grants answer "which columns of
 * those rows". They are different axes and a correct policy does nothing about
 * the second one.
 *
 * A table with `using (user_id = auth.uid())` and `with check (user_id =
 * auth.uid())` is perfectly isolated -- and a user can still rewrite every
 * column of a row that genuinely is theirs, including the one holding their
 * balance, their plan, their role, or their item count. `WITH CHECK` does not
 * help: changing `count` never violates `user_id = auth.uid()`.
 *
 * The same shape exists on INSERT and SELECT. A signup flow that inserts a
 * profile client-side can set `role` at row creation instead of updating it
 * afterwards, and `with check` has no objection because the row genuinely is
 * theirs. A table-wide SELECT grant means every column of their own row is
 * readable. Postgres has no column-level DELETE, so it is three commands.
 * (Credit: u/PeterBuildsSecure on r/Supabase for the INSERT case.)
 *
 * The fix is column-level grants:
 *
 *   revoke insert, update on public.t from authenticated;
 *   grant  insert (email, display_name) on public.t to authenticated;
 *   grant  update (display_name, bio)   on public.t to authenticated;
 *
 * This is deliberately an ADVISORY and never changes the exit code. Supabase's
 * default setup grants table-wide privileges to `authenticated`, so failing CI
 * on this would fail on essentially every project on day one -- and a gate that
 * always fails gets switched off. The tool proves leaks; this observes a risk.
 * Those belong in separate lists.
 */

export interface GrantAdvisory {
  table: string;
  grantee: string;
  /** Which of select/insert/update are still granted table-wide. */
  commands: string[];
  columns: number;
}

export async function checkColumnGrants(
  c: PoolClient, schema: string,
): Promise<GrantAdvisory[]> {
  // has_table_privilege returns false once privileges have been narrowed to
  // specific columns, which makes it a cleaner test than reading
  // information_schema.column_privileges row by row.
  // has_table_privilege returns false once privileges have been narrowed to
  // specific columns, which makes it a cleaner test than reading
  // information_schema.column_privileges row by row. Cast the aggregate to
  // text[]: node-postgres cannot parse name[] and hands back a raw string.
  const { rows } = await c.query(
    `select c.relname as table_name,
            g.grantee,
            array_agg(p.cmd order by p.ord)::text[] as commands,
            (select count(*)::int
               from pg_attribute a
              where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
            ) as columns
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
       cross join (values ('anon'), ('authenticated')) g(grantee)
       cross join lateral (values ('select',1),('insert',2),('update',3)) p(cmd, ord)
      where n.nspname = $1
        and c.relkind in ('r','p')
        and exists (select 1 from pg_roles where rolname = g.grantee)
        and has_table_privilege(g.grantee, c.oid, p.cmd)
      group by c.relname, c.oid, g.grantee
      order by c.relname, g.grantee`,
    [schema],
  );

  return rows.map((r) => ({
    table: `${schema}.${r.table_name}`,
    grantee: r.grantee,
    commands: r.commands,
    columns: r.columns,
  }));
}
