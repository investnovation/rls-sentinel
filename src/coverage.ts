import type { PoolClient } from 'pg';

/**
 * Policy coverage.
 *
 * The honest limit of an attack-based tool: it only tries the situations it set
 * up. A policy like
 *
 *   using (owner_id = auth.uid() or org_id is not null)
 *
 * has two branches. Seeding two rows that differ only by `owner_id` leaves
 * `org_id` NULL, the second branch never fires, and the probe reports OK on a
 * table that in production hands every row to every authenticated user. A
 * confident green on a wide-open table is the worst output this tool could
 * produce.
 *
 * We can't execute every branch -- that's constraint solving over arbitrary SQL
 * -- but we can know when we haven't. Postgres records what each policy
 * actually depends on in pg_depend: every column and every table its expression
 * touches. Structural, exact, no parsing.
 *
 * Compare that against what the probe varied. Anything left over is a branch we
 * never exercised, and the result for that table is UNPROVEN rather than OK.
 */

export interface CoverageGap {
  policy: string;
  untestedColumns: string[];
  untestedTables: string[];
}

export async function checkPolicyCoverage(
  c: PoolClient,
  schema: string,
  table: string,
  variedColumns: Set<string>,
  populatedTables: Set<string>,
): Promise<CoverageGap[]> {
  const { rows } = await c.query(
    `select p.polname                as policy,
            rn.nspname               as ref_schema,
            rc.relname               as ref_table,
            a.attname                as ref_column
       from pg_policy p
       join pg_depend d    on d.objid = p.oid and d.classid = 'pg_policy'::regclass
       join pg_class  rc   on rc.oid = d.refobjid
       join pg_namespace rn on rn.oid = rc.relnamespace
       join pg_attribute a on a.attrelid = d.refobjid and a.attnum = d.refobjsubid
       join pg_class  own  on own.oid = p.polrelid
       join pg_namespace on2 on on2.oid = own.relnamespace
      where on2.nspname = $1 and own.relname = $2
        and d.refobjsubid > 0`,
    [schema, table],
  );

  const byPolicy = new Map<string, CoverageGap>();
  const self = `${schema}.${table}`;

  for (const r of rows) {
    const qualified = `${r.ref_schema}.${r.ref_table}`;
    let gap = byPolicy.get(r.policy);
    if (!gap) {
      gap = { policy: r.policy, untestedColumns: [], untestedTables: [] };
      byPolicy.set(r.policy, gap);
    }

    if (qualified === self) {
      // A column on the table itself that the policy reads. If the probe never
      // varied it, both rows carried the same value and the branch using it was
      // never distinguished.
      if (!variedColumns.has(r.ref_column) && !gap.untestedColumns.includes(r.ref_column)) {
        gap.untestedColumns.push(r.ref_column);
      }
    } else if (!populatedTables.has(qualified)) {
      // The policy consults another table -- a membership or roles table -- that
      // the probe left empty. Every branch depending on it evaluated false for
      // reasons that have nothing to do with whether it is correct.
      if (!gap.untestedTables.includes(qualified)) {
        gap.untestedTables.push(qualified);
      }
    }
  }

  return [...byPolicy.values()].filter(
    (g) => g.untestedColumns.length > 0 || g.untestedTables.length > 0,
  );
}

export function describeGaps(gaps: CoverageGap[]): string {
  const cols = [...new Set(gaps.flatMap((g) => g.untestedColumns))];
  const tabs = [...new Set(gaps.flatMap((g) => g.untestedTables))];
  const parts: string[] = [];
  if (cols.length) parts.push(`column(s) ${cols.join(', ')}`);
  if (tabs.length) parts.push(`table(s) ${tabs.join(', ')}`);
  return `Policies also depend on ${parts.join(' and ')}, which the probe never varied. Untested branch.`;
}
