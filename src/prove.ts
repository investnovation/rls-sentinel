import type { PoolClient } from 'pg';
import { checkPolicyCoverage, describeGaps, type CoverageGap } from './coverage.js';

/**
 * Cross-tenant isolation proof.
 *
 * The whole point: reading pg_policies tells you a policy EXISTS. It does not
 * tell you the policy WORKS. `using (true)` is a policy. It counts. It isolates
 * nothing.
 *
 * So we don't read policies. We seed real rows owned by two synthetic tenants,
 * assume each tenant's identity for real, and try to reach the other one's data.
 * Reads and writes both, because write leaks are worse and almost nobody tests
 * them.
 *
 * Everything runs inside a transaction that is always rolled back. The tool
 * never leaves a row behind.
 */

export const TENANT_A = '00000000-0000-4000-8000-0000000000aa';
export const TENANT_B = '00000000-0000-4000-8000-0000000000bb';

const DELETE_PROBE_MAX_ROWS = 10_000;

const OWNER_COLUMN_CANDIDATES = [
  'user_id', 'owner_id', 'tenant_id', 'profile_id',
  'account_id', 'created_by', 'author_id', 'organization_id', 'org_id',
];

export type Severity = 'critical' | 'high' | 'unproven' | 'ok' | 'skipped';

export interface Finding {
  table: string;
  ownerColumn: string | null;
  rlsEnabled: boolean;
  policyCount: number;
  anonCanRead: boolean;
  crossTenantRead: boolean;
  crossTenantWrite: boolean;
  crossTenantDelete: boolean;
  coverageGaps: CoverageGap[];
  severity: Severity;
  detail: string;
}

interface TableInfo {
  schema: string;
  table: string;
  rlsEnabled: boolean;
  policyCount: number;
  columns: string[];
  pkColumns: string[];
  nullableColumns: string[];
  estRows: number;
}

export async function listTables(c: PoolClient, schema: string): Promise<TableInfo[]> {
  const { rows } = await c.query(
    `select c.relname                    as table,
            c.relrowsecurity             as rls_enabled,
            c.reltuples::bigint          as est_rows,
            count(distinct p.polname)    as policy_count,
            array_agg(distinct a.attname)::text[] as columns,
            array_remove(array_agg(distinct case when i.indisprimary then a.attname end), null)::text[] as pk_columns,
            array_remove(array_agg(distinct case when not a.attnotnull then a.attname end), null)::text[] as nullable_columns
       from pg_class c
       join pg_namespace n  on n.oid = c.relnamespace
       left join pg_policy p on p.polrelid = c.oid
       join pg_attribute a  on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
       left join pg_index i on i.indrelid = c.oid and i.indisprimary and a.attnum = any(i.indkey)
      where n.nspname = $1
        and c.relkind in ('r','p')
      group by c.relname, c.relrowsecurity, c.reltuples
      order by c.relname`,
    [schema],
  );
  return rows.map((r) => ({
    schema,
    table: r.table,
    rlsEnabled: r.rls_enabled,
    policyCount: Number(r.policy_count),
    columns: r.columns as string[],
    pkColumns: r.pk_columns as string[],
    nullableColumns: r.nullable_columns as string[],
    estRows: Number(r.est_rows),
  }));
}

/**
 * A column we can blind-write to: nullable, not part of the primary key, and
 * not the ownership column itself (overwriting that would change who owns the
 * row and muddy the result).
 */
function pickScratchColumn(
  columns: string[], ownerColumn: string, pkColumns: string[],
): string | null {
  return columns.find(
    (col) => col !== ownerColumn && !pkColumns.includes(col),
  ) ?? null;
}

/**
 * Find a single-column foreign key on a given column.
 *
 * Returns schema and table separately so the result can be fed back in and the
 * chain walked. Real schemas nest: `memory.user_id` -> `profiles.id` ->
 * `auth.users.id`. Seeding only the first level fails on the second.
 */
async function findForeignKey(
  c: PoolClient, schema: string, table: string, column: string,
): Promise<{ refSchema: string; refTable: string; refColumn: string } | null> {
  const { rows } = await c.query(
    `select rn.nspname as ref_schema,
            rc.relname as ref_table,
            ra.attname as ref_column
       from pg_constraint con
       join pg_class      c1 on c1.oid = con.conrelid
       join pg_namespace  n1 on n1.oid = c1.relnamespace
       join pg_attribute  a  on a.attrelid = con.conrelid and a.attnum = con.conkey[1]
       join pg_class      rc on rc.oid = con.confrelid
       join pg_namespace  rn on rn.oid = rc.relnamespace
       join pg_attribute  ra on ra.attrelid = con.confrelid and ra.attnum = con.confkey[1]
      where con.contype = 'f'
        and n1.nspname = $1 and c1.relname = $2
        and a.attname = $3
        and array_length(con.conkey, 1) = 1
      limit 1`,
    [schema, table, column],
  );
  return rows.length
    ? { refSchema: rows[0].ref_schema, refTable: rows[0].ref_table, refColumn: rows[0].ref_column }
    : null;
}

/**
 * Seed the synthetic tenants up an entire foreign key chain, deepest first.
 *
 * `memory.user_id` -> `profiles.id` -> `auth.users.id` means auth.users has to
 * be populated before profiles, and profiles before memory. Depth-limited so a
 * self-referencing or cyclic schema can't spin forever.
 */
async function seedFkChain(
  c: PoolClient, schema: string, table: string, column: string, depth = 0,
): Promise<void> {
  if (depth > 5) return;
  const parent = await findForeignKey(c, schema, table, column);
  if (parent) {
    await seedFkChain(c, parent.refSchema, parent.refTable, parent.refColumn, depth + 1);
    await c.query(
      `insert into "${parent.refSchema}"."${parent.refTable}" ("${parent.refColumn}")
         values ($1), ($2) on conflict do nothing`,
      [TENANT_A, TENANT_B],
    );
  }
}

function pickOwnerColumn(columns: string[]): string | null {
  for (const candidate of OWNER_COLUMN_CANDIDATES) {
    if (columns.includes(candidate)) return candidate;
  }
  return null;
}

/** Assume a Supabase end-user identity for the remainder of the transaction. */
async function becomeUser(c: PoolClient, role: string, sub: string | null) {
  await c.query(`set local role ${role}`);
  const claims = sub
    ? JSON.stringify({ sub, role })
    : JSON.stringify({ role });
  await c.query(`select set_config('request.jwt.claims', $1, true)`, [claims]);
}

async function resetRole(c: PoolClient) {
  await c.query('reset role');
}

/**
 * How a table's rows are tied to a user.
 *
 *  - direct: the table carries the ownership column itself.
 *  - join:   the table owns nothing; it belongs to a user through a parent.
 *            `messages` has no user_id, only conversation_id, and the
 *            conversation is what belongs to someone. Most real schemas have
 *            tables like this, and they are usually the ones holding the
 *            content that actually matters.
 */
type OwnershipPlan =
  | { kind: 'direct'; column: string }
  | {
      kind: 'join'; fkColumn: string;
      parentSchema: string; parentTable: string;
      parentPk: string; parentOwner: string;
    };

async function resolveOwnership(
  c: PoolClient, t: TableInfo,
): Promise<OwnershipPlan | null> {
  const direct = pickOwnerColumn(t.columns);
  if (direct) return { kind: 'direct', column: direct };

  // Ownership by primary key: Supabase's profile pattern, where the PK is the
  // user id and carries an FK straight to auth.users.
  if (t.pkColumns.length === 1) {
    const pkFk = await findForeignKey(c, t.schema, t.table, t.pkColumns[0]);
    if (pkFk && pkFk.refSchema === 'auth' && pkFk.refTable === 'users') {
      return { kind: 'direct', column: t.pkColumns[0] };
    }
  }

  // Ownership through a join: find an FK pointing at a table that does have an
  // ownership column, and test through it.
  for (const col of t.columns) {
    if (t.pkColumns.includes(col)) continue;
    const fk = await findForeignKey(c, t.schema, t.table, col);
    if (!fk) continue;

    const { rows } = await c.query(
      `select array_agg(a.attname)::text[] as cols,
              (select ra.attname
                 from pg_index i
                 join pg_attribute ra on ra.attrelid = i.indrelid
                                     and ra.attnum = i.indkey[0]
                where i.indrelid = c.oid and i.indisprimary
                limit 1) as pk
         from pg_class c
         join pg_namespace n on n.oid = c.relnamespace
         join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
        where n.nspname = $1 and c.relname = $2
        group by c.oid`,
      [fk.refSchema, fk.refTable],
    );
    if (!rows.length) continue;

    const parentOwner = pickOwnerColumn(rows[0].cols as string[]);
    if (parentOwner && rows[0].pk) {
      return {
        kind: 'join', fkColumn: col,
        parentSchema: fk.refSchema, parentTable: fk.refTable,
        parentPk: rows[0].pk, parentOwner,
      };
    }
  }

  return null;
}

/**
 * Seed one row for each synthetic tenant and return the column/value pair that
 * distinguishes them. For direct ownership that is the ownership column itself;
 * for join ownership it is the foreign key, pointing at parent rows that belong
 * to different people.
 */
async function seedTenants(
  c: PoolClient, t: TableInfo, plan: OwnershipPlan,
): Promise<{ column: string; valueB: unknown }> {
  const qualified = `"${t.schema}"."${t.table}"`;

  if (plan.kind === 'direct') {
    await seedFkChain(c, t.schema, t.table, plan.column);
    await c.query(
      `insert into ${qualified} ("${plan.column}") values ($1), ($2)`,
      [TENANT_A, TENANT_B],
    );
    return { column: plan.column, valueB: TENANT_B };
  }

  const parentQ = `"${plan.parentSchema}"."${plan.parentTable}"`;
  await seedFkChain(c, plan.parentSchema, plan.parentTable, plan.parentOwner);
  const parents = await c.query(
    `insert into ${parentQ} ("${plan.parentOwner}") values ($1), ($2)
       returning "${plan.parentPk}" as pk`,
    [TENANT_A, TENANT_B],
  );
  const [pa, pb] = parents.rows.map((r) => r.pk);
  await c.query(
    `insert into ${qualified} ("${plan.fkColumn}") values ($1), ($2)`,
    [pa, pb],
  );
  return { column: plan.fkColumn, valueB: pb };
}

export async function proveTable(c: PoolClient, t: TableInfo): Promise<Finding> {
  const qualified = `"${t.schema}"."${t.table}"`;
  const plan = await resolveOwnership(c, t);

  const base: Finding = {
    table: `${t.schema}.${t.table}`,
    ownerColumn:
      plan?.kind === 'direct' ? plan.column
      : plan?.kind === 'join' ? `${plan.fkColumn} -> ${plan.parentTable}.${plan.parentOwner}`
      : null,
    rlsEnabled: t.rlsEnabled,
    policyCount: t.policyCount,
    anonCanRead: false,
    crossTenantRead: false,
    crossTenantWrite: false,
    crossTenantDelete: false,
    coverageGaps: [],
    severity: 'ok',
    detail: '',
  };

  if (!plan) {
    return {
      ...base, severity: 'skipped',
      detail: 'No ownership found, directly or through a foreign key.',
    };
  }

  await c.query('savepoint probe');
  let disc: { column: string; valueB: unknown };
  try {
    disc = await seedTenants(c, t, plan);
  } catch (err: any) {
    await c.query('rollback to savepoint probe');
    return {
      ...base, severity: 'skipped',
      detail: `Could not seed test rows: ${err.message.split('\n')[0]}`,
    };
  }

  try {
    // Probe 1: what can an unauthenticated caller see?
    await becomeUser(c, 'anon', null);
    const anonRead = await c.query(`select count(*)::int as n from ${qualified}`);
    base.anonCanRead = anonRead.rows[0].n > 0;
    await resetRole(c);

    // Probe 2: can tenant A read tenant B's rows?
    await becomeUser(c, 'authenticated', TENANT_A);
    const crossRead = await c.query(
      `select count(*)::int as n from ${qualified} where "${disc.column}" = $1`,
      [disc.valueB],
    );
    base.crossTenantRead = crossRead.rows[0].n > 0;
    await resetRole(c);

    // Probe 3: blind write. See the note in the README -- a targeted write is
    // masked by a correct SELECT policy, so only a blind one tests the UPDATE
    // policy in isolation. ctid detects which rows were really touched.
    const scratch = pickScratchColumn(t.nullableColumns, disc.column, t.pkColumns);
    if (scratch) {
      const before = await c.query(
        `select ctid::text as x from ${qualified} where "${disc.column}" = $1`,
        [disc.valueB],
      );
      await becomeUser(c, 'authenticated', TENANT_A);
      try { await c.query(`update ${qualified} set "${scratch}" = null`); } catch { /* denied */ }
      await resetRole(c);
      const after = await c.query(
        `select ctid::text as x from ${qualified} where "${disc.column}" = $1`,
        [disc.valueB],
      );
      base.crossTenantWrite =
        before.rows.length > 0 && after.rows.length > 0 &&
        before.rows[0].x !== after.rows[0].x;
    }

    // Probe 4: blind delete. Same shape, worse consequence. Bounded by row
    // count so we never lock up a large table to make a point.
    if (t.estRows <= DELETE_PROBE_MAX_ROWS) {
      await c.query('savepoint del');
      const beforeDel = await c.query(
        `select count(*)::int as n from ${qualified} where "${disc.column}" = $1`,
        [disc.valueB],
      );
      await becomeUser(c, 'authenticated', TENANT_A);
      try { await c.query(`delete from ${qualified}`); } catch { /* denied */ }
      await resetRole(c);
      const afterDel = await c.query(
        `select count(*)::int as n from ${qualified} where "${disc.column}" = $1`,
        [disc.valueB],
      );
      base.crossTenantDelete = beforeDel.rows[0].n > 0 && afterDel.rows[0].n === 0;
      await c.query('rollback to savepoint del');
    }
    // What did this probe actually exercise? Everything else in the policy is
    // a branch we never reached.
    const varied = new Set<string>([disc.column]);
    const populated = new Set<string>([`${t.schema}.${t.table}`]);
    if (plan.kind === 'join') {
      varied.add(plan.parentOwner);
      populated.add(`${plan.parentSchema}.${plan.parentTable}`);
    }
    base.coverageGaps =
      await checkPolicyCoverage(c, t.schema, t.table, varied, populated);
  } finally {
    await c.query('rollback to savepoint probe');
    await resetRole(c);
  }

  if (base.crossTenantDelete) {
    base.severity = 'critical';
    base.detail = 'Tenant A DELETED tenant B rows. Any user can empty this table.';
  } else if (base.crossTenantWrite) {
    base.severity = 'critical';
    base.detail = 'Tenant A MODIFIED tenant B rows. Write isolation is broken.';
  } else if (base.anonCanRead) {
    base.severity = 'critical';
    base.detail = 'Unauthenticated caller read rows. The anon key ships in your client bundle.';
  } else if (base.crossTenantRead) {
    base.severity = 'critical';
    base.detail = 'Tenant A read tenant B rows. Read isolation is broken.';
  } else if (t.rlsEnabled && t.policyCount === 0) {
    base.severity = 'high';
    base.detail = 'RLS on with zero policies: locked to everyone, including your app.';
  } else if (base.coverageGaps.length) {
    base.severity = 'unproven';
    base.detail = describeGaps(base.coverageGaps);
  } else {
    base.severity = 'ok';
    base.detail = 'Isolation held under read, write and delete probes.';
  }

  return base;
}
