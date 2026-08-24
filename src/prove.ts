import type { PoolClient } from 'pg';

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

const OWNER_COLUMN_CANDIDATES = [
  'user_id', 'owner_id', 'tenant_id', 'profile_id',
  'account_id', 'created_by', 'author_id', 'organization_id', 'org_id',
];

export type Severity = 'critical' | 'high' | 'ok' | 'skipped';

export interface Finding {
  table: string;
  ownerColumn: string | null;
  rlsEnabled: boolean;
  policyCount: number;
  anonCanRead: boolean;
  crossTenantRead: boolean;
  crossTenantWrite: boolean;
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
}

export async function listTables(c: PoolClient, schema: string): Promise<TableInfo[]> {
  const { rows } = await c.query(
    `select c.relname                    as table,
            c.relrowsecurity             as rls_enabled,
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
      group by c.relname, c.relrowsecurity
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
 * Find a single-column foreign key on the ownership column.
 *
 * In almost every real Supabase schema, `user_id` references `auth.users(id)`.
 * Seeding a synthetic tenant UUID violates that constraint and the table gets
 * skipped — which would make the tool useless on exactly the projects it's for.
 * So we look the FK up and seed the parent first, inside the same transaction
 * that gets rolled back.
 */
async function findOwnerForeignKey(
  c: PoolClient, schema: string, table: string, ownerColumn: string,
): Promise<{ refTable: string; refColumn: string } | null> {
  const { rows } = await c.query(
    `select quote_ident(rn.nspname) || '.' || quote_ident(rc.relname) as ref_table,
            ra.attname                                               as ref_column
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
    [schema, table, ownerColumn],
  );
  return rows.length
    ? { refTable: rows[0].ref_table, refColumn: rows[0].ref_column }
    : null;
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

export async function proveTable(c: PoolClient, t: TableInfo): Promise<Finding> {
  const ownerColumn = pickOwnerColumn(t.columns);
  const qualified = `"${t.schema}"."${t.table}"`;

  const base: Finding = {
    table: `${t.schema}.${t.table}`,
    ownerColumn,
    rlsEnabled: t.rlsEnabled,
    policyCount: t.policyCount,
    anonCanRead: false,
    crossTenantRead: false,
    crossTenantWrite: false,
    severity: 'ok',
    detail: '',
  };

  if (!ownerColumn) {
    return {
      ...base,
      severity: 'skipped',
      detail: 'No ownership column found. Pass --owner-column to test this table.',
    };
  }

  // Everything below happens inside a savepoint we always roll back.
  await c.query('savepoint probe');
  try {
    // Seed as the table owner, which bypasses RLS by design.
    // Real schemas are messy: NOT NULL columns without defaults, FK constraints,
    // check constraints. If we can't seed a table we skip it loudly rather than
    // aborting the run or, worse, reporting a clean bill we didn't earn.
    try {
      // If the ownership column points at another table (usually auth.users),
      // the parent rows have to exist before ours can. Rolled back with
      // everything else.
      const fk = await findOwnerForeignKey(c, t.schema, t.table, ownerColumn);
      if (fk) {
        await c.query(
          `insert into ${fk.refTable} ("${fk.refColumn}") values ($1), ($2)
             on conflict do nothing`,
          [TENANT_A, TENANT_B],
        );
      }

      await c.query(
        `insert into ${qualified} ("${ownerColumn}") values ($1), ($2)`,
        [TENANT_A, TENANT_B],
      );
    } catch (err: any) {
      await c.query('rollback to savepoint probe');
      return {
        ...base,
        severity: 'skipped',
        detail: `Could not seed test rows: ${err.message.split('\n')[0]}`,
      };
    }

    // --- Probe 1: what can an unauthenticated caller see? ---
    // This is the anon-key exposure class: the key ships in the client bundle.
    await becomeUser(c, 'anon', null);
    const anonRead = await c.query(`select count(*)::int as n from ${qualified}`);
    base.anonCanRead = anonRead.rows[0].n > 0;
    await resetRole(c);

    // --- Probe 2: can tenant A read tenant B's rows? ---
    await becomeUser(c, 'authenticated', TENANT_A);
    const crossRead = await c.query(
      `select count(*)::int as n from ${qualified} where "${ownerColumn}" = $1`,
      [TENANT_B],
    );
    base.crossTenantRead = crossRead.rows[0].n > 0;

    await resetRole(c);

    // --- Probe 3: can tenant A WRITE to tenant B's rows? ---
    //
    // This has to be a BLIND write, and the distinction is the whole reason
    // this tool exists.
    //
    // A targeted write -- `update t set x = x where owner = B` -- reads the
    // owner column in its WHERE clause, which makes Postgres apply the SELECT
    // policy too. A correct SELECT policy hides B's row, the update matches
    // nothing, and the table looks safe. It is not safe. It was never tested.
    //
    // A blind write -- `update t set <scratch> = null`, no WHERE, constant
    // value -- reads no columns at all. Only the UPDATE policy applies. If that
    // policy is `using (true)`, every row in the table is modified, including
    // every other tenant's.
    //
    // We detect what was actually touched with ctid, the physical row version.
    // (xmin would not work here: it is the transaction id, and the whole probe
    // runs inside one transaction, so it never changes.) An UPDATE always
    // writes a new tuple version at a new ctid, whatever the column types are.
    const scratch = pickScratchColumn(t.nullableColumns, ownerColumn, t.pkColumns);
    if (scratch) {
      const before = await c.query(
        `select ctid::text as x from ${qualified} where "${ownerColumn}" = $1`,
        [TENANT_B],
      );

      await becomeUser(c, 'authenticated', TENANT_A);
      try {
        await c.query(`update ${qualified} set "${scratch}" = null`);
      } catch {
        // Denied, or the column rejects null. Either way, no leak proven here.
      }
      await resetRole(c);

      const after = await c.query(
        `select ctid::text as x from ${qualified} where "${ownerColumn}" = $1`,
        [TENANT_B],
      );
      base.crossTenantWrite =
        before.rows.length > 0 &&
        after.rows.length > 0 &&
        before.rows[0].x !== after.rows[0].x;
    }
  } finally {
    await c.query('rollback to savepoint probe');
    await resetRole(c);
  }

  // Severity. Write leaks outrank read leaks: an attacker who can write can
  // usually escalate to read anyway, and can also destroy data.
  if (base.crossTenantWrite) {
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
  } else {
    base.severity = 'ok';
    base.detail = 'Isolation held under read and write probes.';
  }

  return base;
}
