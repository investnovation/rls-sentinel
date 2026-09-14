#!/usr/bin/env node
import { Pool } from 'pg';
import { listTables, proveTable, type Finding } from './prove.js';
import { assessSafety } from './safety.js';
import { checkColumnGrants, type GrantAdvisory } from './grants.js';
import { checkSecurityDefiners, type DefinerFinding } from './definers.js';

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
const strict = args.includes('--strict');
const ssl = isLocal ? undefined : { rejectUnauthorized: !insecure };

const c = (code: string, s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s: string) => c('31', s);
const yellow = (s: string) => c('33', s);
const green = (s: string) => c('32', s);
const dim = (s: string) => c('2', s);
const bold = (s: string) => c('1', s);

function render(findings: Finding[], grants: GrantAdvisory[], definers: DefinerFinding[]) {
  const leaks = findings.filter((f) => f.severity === 'critical');
  const warns = findings.filter((f) => f.severity === 'high');
  const unproven = findings.filter((f) => f.severity === 'unproven');
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
      f.crossTenantDelete ? red('cross-delete') : null,
    ]
      .filter(Boolean)
      .join(' ');

  for (const f of [...leaks, ...warns, ...unproven, ...ok, ...skipped]) {
    const badge =
      f.severity === 'critical' ? red('  LEAK  ')
      : f.severity === 'high'   ? yellow('  WARN  ')
      : f.severity === 'unproven' ? yellow('UNPROVEN')
      : f.severity === 'skipped' ? dim('  SKIP  ')
      :                            green('   OK   ');
    console.log(`${badge} ${f.table.padEnd(28)} ${marks(f)}`);
    if (f.severity !== 'ok') console.log(dim(`         ${f.detail}`));
  }

  // A skipped table was not proven, so it cannot be reported as clean. The
  // whole claim of this tool is proof rather than inference; a green line
  // covering tables it never probed would be the same inference it refuses.
  const probed = leaks.length + warns.length + unproven.length + ok.length;

  console.log('');
  if (leaks.length) {
    console.log(red(bold(`  ${leaks.length} table(s) leaked across tenants.`)));
    console.log(dim('  These were proven with real seeded rows, not inferred from policy text.'));
  } else if (probed > 0) {
    console.log(green(bold(`  No cross-tenant leaks found in the ${probed} table(s) probed.`)));
  } else {
    console.log(yellow(bold('  Nothing was proven. Every table was skipped.')));
    console.log(dim('  This is not a pass. See the reason on each SKIP above.'));
  }
  if (unproven.length) {
    console.log(yellow(`  ${unproven.length} table(s) UNPROVEN — no leak found, but the policy has`));
    console.log(yellow(`  branches this probe never reached. Not the same as safe.`));
    if (!strict) console.log(dim('  Use --strict to fail the build on these.'));
  }
  if (skipped.length) {
    console.log(dim(`  ${skipped.length} table(s) skipped, and therefore not proven either way.`));
    console.log(dim('  The reason is printed against each one above.'));
  }

  if (definers.length) {
    console.log('');
    console.log(yellow(`  UNPROVEN — ${definers.length} SECURITY DEFINER function(s) reachable by a client role:`));
    for (const d of definers.slice(0, 6)) {
      console.log(`    ${d.signature}`);
      const bits = [
        `runs as ${d.owner}`,
        d.reachableBy,
        d.searchPathPinned ? 'search_path pinned' : 'search_path NOT pinned',
      ];
      console.log(dim(`      ${bits.join(' · ')}`));
      if (!d.referencesIdentity) {
        console.log(dim('      body never references auth.uid, auth.jwt or current_setting'));
      }
      console.log(dim(`      ${d.revoke}`));
    }
    if (definers.length > 6) console.log(dim(`    ... and ${definers.length - 6} more`));
    console.log(dim('  These run as their owner, so RLS is never evaluated inside them.'));
    console.log(dim('  This tool does not read function bodies to decide whether they are'));
    console.log(dim('  safe. It reports that the surface is reachable, not that calling it'));
    console.log(dim('  is harmful. That needs a person.'));
    if (!strict) console.log(dim('  Use --strict to fail on the ones that enforce nothing.'));
  }

  if (grants.length) {
    const tables = [...new Set(grants.map((g) => g.table))];
    console.log('');
    console.log(yellow(`  Advisory — ${tables.length} table(s) grant table-wide privileges to a client role:`));
    for (const t of tables.slice(0, 8)) {
      for (const g of grants.filter((x) => x.table === t)) {
        const cmds = g.commands.join(', ');
        console.log(dim(`    ${t.padEnd(28)} ${g.grantee.padEnd(14)} ${cmds} — all ${g.columns} columns`));
      }
    }
    if (tables.length > 8) console.log(dim(`    ... and ${tables.length - 8} more`));
    console.log(dim('  RLS decides which rows. Grants decide which columns. A correct'));
    console.log(dim('  policy still lets a user read or rewrite any column of their own'));
    console.log(dim('  row, and set any column at insert time.'));
    console.log(dim('  Narrow it:  revoke insert, update on t from authenticated;'));
    console.log(dim('              grant  insert (email) on t to authenticated;'));
    console.log(dim('              grant  update (bio)   on t to authenticated;'));
    console.log(dim('  Column privileges cover select, insert and update. Postgres has'));
    console.log(dim('  no column-level delete.'));
    console.log(dim('  Advisory only — does not affect the exit code.'));
  }

  // Only when something was actually found. On a clean run this is a pitch;
  // on a run that printed LEAK or UNPROVEN it is the honest next question,
  // because the reader has just been told what this tool proves and is
  // entitled to know what it does not.
  if (leaks.length || unproven.length || definers.length) {
    console.log('');
    console.log(dim('  What this tool cannot reach, and where the rest of the leaks live:'));
    console.log(dim('    SECURITY DEFINER function bodies      storage bucket policies'));
    console.log(dim('    service-role key handling             auth configuration'));
    console.log(dim('    views without security_invoker        owner and BYPASSRLS exemption'));
    console.log('');
    console.log(dim(`  Those get checked by hand:    ${bold('investnovation.com/audit')}`));
    console.log(dim(`  Shipping this for a client?   ${bold('investnovation.com/agencies')}`));
  }

  console.log('');
}

(async () => {
  const pool = new Pool({ connectionString, ssl });
  const client = await pool.connect();
  const findings: Finding[] = [];
  let grants: GrantAdvisory[] = [];
  let definers: DefinerFinding[] = [];

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

    grants = await checkColumnGrants(client, schema);
    definers = await checkSecurityDefiners(client, schema);
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
    console.log(JSON.stringify({ schema, findings, columnGrantAdvisories: grants, securityDefiners: definers }, null, 2));
  } else {
    render(findings, grants, definers);
  }

  // Non-zero exit is the entire point: this is a CI gate, not a report.
  // A proven leak always fails. UNPROVEN is honest uncertainty rather than a
  // finding, so it only fails under --strict -- a gate that fires on every
  // org-scoped policy would be switched off within a week.
  // --strict fails only on definers that are exposed by default AND never
  // mention an identity source. A pinned, identity-checking helper that
  // somebody granted deliberately is not a finding, and failing on it would
  // fire on every real project.
  const unownedDefiners = definers.filter((d) => d.publicByDefault && !d.referencesIdentity);
  const fail =
    findings.some((f) => f.severity === 'critical' || (strict && f.severity === 'unproven')) ||
    (strict && unownedDefiners.length > 0);
  process.exit(fail ? 1 : 0);
})().catch((err) => {
  console.error('rls-sentinel: ' + err.message);
  process.exit(2);
});
