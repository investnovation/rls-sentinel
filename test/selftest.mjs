/**
 * Self-test.
 *
 * A tool that proves other people's isolation should prove its own. This loads
 * both fixtures into a real Postgres, runs the CLI, and asserts every expected
 * finding — including the negative ones, which matter more. If a change makes
 * the tool report a leak on a correctly-secured table, that is a false positive
 * shipped to someone's CI, and this catches it.
 */
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import pg from 'pg';

const DB = process.env.DATABASE_URL;
if (!DB) {
  console.error('set DATABASE_URL');
  process.exit(2);
}

/** table -> the exact leak flags it must report. */
const EXPECT = {
  // Direct ownership
  'public.documents':   { read: false, write: false, del: false, anon: false },
  'public.notes':       { read: true,  write: false, del: false, anon: true  },
  'public.invoices':    { read: false, write: true,  del: false, anon: false },
  'public.receipts':    { read: false, write: false, del: true,  anon: false },
  // Ownership by primary key (Supabase profile pattern)
  'public.profiles':    { read: false, write: false, del: false, anon: false },
  // Two-level FK chain: -> profiles -> auth.users
  'public.conversations': { read: false, write: false, del: false, anon: false },
  'public.memory':        { read: false, write: false, del: false, anon: false },
  // Ownership through a join: messages -> conversations.user_id
  'public.messages':    { read: false, write: false, del: true,  anon: false },
};

const pool = new pg.Pool({ connectionString: DB });
const c = await pool.connect();
// Start from nothing. Leftover accounts would trip the production guard, which
// is correct behaviour but not what we're testing here.
await c.query('drop schema if exists public cascade');
await c.query('create schema public');
await c.query('grant usage, create on schema public to public');
await c.query('drop schema if exists auth cascade');
for (const f of ['fixture.sql', 'real-fixture.sql']) {
  await c.query(readFileSync(new URL(`../${f}`, import.meta.url), 'utf8'));
}
c.release();
await pool.end();

let out;
try {
  out = execFileSync('npx', ['tsx', 'src/index.ts', '--db', DB, '--json'], {
    encoding: 'utf8',
  });
} catch (e) {
  // Exit 1 is expected: the fixtures contain deliberate leaks.
  out = e.stdout;
  if (e.status !== 1) {
    console.error(`expected exit 1, got ${e.status}`);
    console.error(e.stderr);
    process.exit(1);
  }
}

const { findings } = JSON.parse(out);
const byTable = Object.fromEntries(findings.map((f) => [f.table, f]));

let failed = 0;
for (const [table, want] of Object.entries(EXPECT)) {
  const got = byTable[table];
  if (!got) {
    console.error(`FAIL ${table}: not in output`);
    failed++;
    continue;
  }
  if (got.severity === 'skipped') {
    console.error(`FAIL ${table}: skipped — ${got.detail}`);
    failed++;
    continue;
  }
  const actual = {
    read: got.crossTenantRead, write: got.crossTenantWrite,
    del: got.crossTenantDelete, anon: got.anonCanRead,
  };
  const diff = Object.keys(want).filter((k) => want[k] !== actual[k]);
  if (diff.length) {
    console.error(`FAIL ${table}: ${diff.map((k) =>
      `${k} expected ${want[k]}, got ${actual[k]}`).join('; ')}`);
    failed++;
  } else {
    console.log(`  ok  ${table}`);
  }
}

console.log('');
if (failed) {
  console.error(`${failed} of ${Object.keys(EXPECT).length} checks failed.`);
  process.exit(1);
}
console.log(`All ${Object.keys(EXPECT).length} checks passed.`);
