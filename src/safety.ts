import type { PoolClient } from 'pg';

/**
 * Production guard.
 *
 * This tool inserts rows, runs updates, and rolls everything back. Rollback
 * covers the data. It does not cover everything:
 *
 *   - Sequences are non-transactional. Inserting into a table with a bigserial
 *     primary key permanently consumes id values, even after a rollback. Cosmetic
 *     on its own, alarming if someone is watching for gaps.
 *
 *   - Triggers fire before the rollback happens. A trigger that writes to an
 *     audit table gets rolled back with everything else, but one that calls out
 *     over the network -- pg_net, a webhook, an email, a queue insert in another
 *     system -- has already left the database. That cannot be undone.
 *
 *   - Locks are held for the duration. On a busy production table, a probe that
 *     stalls holds row locks until it finishes or the connection dies.
 *
 * So: detect a likely-live database and refuse unless the operator says
 * otherwise, explicitly and in a flag they had to type on purpose.
 */

const HOSTNAME_HINTS = /prod|production|live/i;
const AUTH_USER_THRESHOLD = 25;
const TABLE_ROW_THRESHOLD = 1000;

export interface SafetyReport {
  looksProduction: boolean;
  reasons: string[];
  triggerTables: string[];
  sequenceTables: string[];
}

export async function assessSafety(
  c: PoolClient,
  schema: string,
  connectionString: string,
): Promise<SafetyReport> {
  const reasons: string[] = [];

  if (HOSTNAME_HINTS.test(connectionString)) {
    reasons.push('Connection string contains "prod", "production", or "live".');
  }

  // Real user accounts are the clearest signal a Supabase project is live.
  try {
    const { rows } = await c.query(
      `select count(*)::int as n from auth.users`,
    );
    if (rows[0].n > AUTH_USER_THRESHOLD) {
      reasons.push(`auth.users contains ${rows[0].n} accounts.`);
    }
  } catch {
    // No auth schema (plain Postgres) or no permission. Not a signal either way.
  }

  // Estimated row counts from the planner's statistics -- no table scan.
  const { rows: big } = await c.query(
    `select c.relname, c.reltuples::bigint as est
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = $1 and c.relkind in ('r','p') and c.reltuples > $2
      order by c.reltuples desc limit 3`,
    [schema, TABLE_ROW_THRESHOLD],
  );
  if (big.length) {
    const list = big.map((r) => `${r.relname} (~${r.est})`).join(', ');
    reasons.push(`Tables carrying substantial data: ${list}.`);
  }

  // Triggers whose side effects may escape the transaction.
  const { rows: trig } = await c.query(
    `select distinct c.relname
       from pg_trigger t
       join pg_class c     on c.oid = t.tgrelid
       join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = $1 and not t.tgisinternal
      order by c.relname`,
    [schema],
  );

  // Tables whose primary key burns a sequence value on every insert.
  const { rows: seq } = await c.query(
    `select distinct c.relname
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
       join pg_attribute a on a.attrelid = c.oid and a.attnum > 0
       join pg_attrdef  d on d.adrelid = c.oid and d.adnum = a.attnum
      where n.nspname = $1
        and c.relkind in ('r','p')
        and pg_get_expr(d.adbin, d.adrelid) like 'nextval%'
      order by c.relname`,
    [schema],
  );

  return {
    looksProduction: reasons.length > 0,
    reasons,
    triggerTables: trig.map((r) => r.relname),
    sequenceTables: seq.map((r) => r.relname),
  };
}
