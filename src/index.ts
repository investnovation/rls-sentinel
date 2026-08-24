#!/usr/bin/env node
import { Pool } from 'pg';
import { listTables, proveTable, type Finding } from './prove.js';
import { assessSafety } from './safety.js';

const args = process.argv.slice(2);
const flag = (name: string, fallback?: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};

const connectionString = flag('db', process.env.DATABASE_URL);
const schema = flag('schema', 'public')!;
const asJson = args.includes('--json');

if (!connectionString) {
  console.error('rls-sentinel: pass --db <connection-string> or set DATABASE_URL');
  process.exit(2);
}

const COLOR = process.stdout.isTTY && !asJson;

// Hosted Postgres (Supabase, Neon, RDS) requires TLS; a local unix socket or
// localhost does not. Detect rather than making the user think about it.
const isLocal = /localhost|127\.0\.0\.1|host=\/|\.sock/.test(connectionString);
const insecure = args.includes('--insecure');
const allowProduction = args.includes('--allow-production');
const ssl = isLocal ? undefined : { rejectUnauthorized: !insecure };

const c = (code: string, s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s: string) => c('31', s);
const yellow = (s: string) => c('33', s);
const green = (s: string) => c('32', s);
const dim = (s: string) => c('2', s);
const bold = (s: string) => c('1', s);

function render(findings: Finding[]) {
  const leaks = findings.filter((f) => f.severity === 'critical');
  const warns = findings.filter((f) => f.severity === 'high');
  const skipped = findings.filter((f) => f.severity === 'skipped');
  const ok = findings.filter((f) => f.severity === 'ok');

  console.log('');
  console.log(bold('  RLS Sentinel — cross-tenant isolation proof'));
  console.log(dim(`  ${findings.length} tables in schema "${schema}"`));
  console.log('');

  const marks = (f: Finding) =>
    [
      f.anonCanRead ? red('anon-read') : null,
      f.crossTenantRead ? red('cross-read') : null,
      f.crossTenantWrite ? red('cross-write') : null,
    ]
      .filter(Boolean)
      .join(' ');

  for (const f of [...leaks, ...warns, ...ok, ...skipped]) {
    const badge =
      f.severity === 'critical' ? red('  LEAK  ')
      : f.severity === 'high'   ? yellow('  WARN  ')
      : f.severity === 'skipped' ? dim('  SKIP  ')
      :                            green('   OK   ');
    console.log(`${badge} ${f.table.padEnd(28)} ${marks(f)}`);
    if (f.severity !== 'ok') console.log(dim(`         ${f.detail}`));
  }

  console.log('');
  if (leaks.length) {
    console.log(red(bold(`  ${leaks.length} table(s) leaked across tenants.`)));
    console.log(dim('  These were proven with real seeded rows, not inferred from policy text.'));
  } else {
    console.log(green(bold('  No cross-tenant leaks found.')));
  }
  if (skipped.length) {
    console.log(dim(`  ${skipped.length} skipped (no ownership column detected).`));
  }
  console.log('');
}

(async () => {
  const pool = new Pool({ connectionString, ssl });
  const client = await pool.connect();
  const findings: Finding[] = [];

  try {
    // One outer transaction. Nothing we do is ever committed.
    await client.query('begin');

    // Guard before we write anything.
    const safety = await assessSafety(client, schema, connectionString);
    if (safety.looksProduction && !allowProduction) {
      console.error('');
      console.error(red(bold('  Refusing to run: this looks like a live database.')));
      for (const r of safety.reasons) console.error(`    - ${r}`);
      console.error('');
      console.error('  This tool inserts rows and runs updates. It rolls all of it back,');
      console.error('  but rollback does not undo everything:');
      if (safety.sequenceTables.length) {
        console.error(dim(`    - Sequence values are consumed permanently (${safety.sequenceTables.length} table(s) affected).`));
      }
      if (safety.triggerTables.length) {
        console.error(dim(`    - Triggers fire before rollback: ${safety.triggerTables.join(', ')}.`));
        console.error(dim('      Anything one of them sends over the network has already left.'));
      }
      console.error(dim('    - Row locks are held for the duration of the probe.'));
      console.error('');
      console.error('  Point it at a branch or staging database instead.');
      console.error(dim('  If you have read the above and still want to continue: --allow-production'));
      console.error('');
      await client.query('rollback');
      client.release();
      await pool.end();
      process.exit(3);
    }

    if (safety.triggerTables.length && !asJson) {
      console.log('');
      console.log(yellow(`  Note: triggers exist on ${safety.triggerTables.join(', ')}.`));
      console.log(dim('  Trigger side effects that leave the database are not rolled back.'));
    }

    const tables = await listTables(client, schema);
    for (const t of tables) {
      findings.push(await proveTable(client, t));
    }
  } finally {
    await client.query('rollback');
    client.release();
    await pool.end();
  }

  if (asJson) {
    console.log(JSON.stringify({ schema, findings }, null, 2));
  } else {
    render(findings);
  }

  // Non-zero exit is the entire point: this is a CI gate, not a report.
  process.exit(findings.some((f) => f.severity === 'critical') ? 1 : 0);
})().catch((err) => {
  console.error('rls-sentinel: ' + err.message);
  process.exit(2);
});
