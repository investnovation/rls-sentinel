import type { PoolClient } from 'pg';

/**
 * SECURITY DEFINER exposure.
 *
 * A `SECURITY DEFINER` function runs as its owner, not its caller, so RLS is
 * never evaluated inside it. Postgres grants `EXECUTE` to `PUBLIC` on every
 * function at creation, which means a function written for a trigger or a
 * server path, that nobody ever granted anything on, is callable with the anon
 * key that ships in your client bundle.
 *
 * Verified: on a table where `anon` has no privileges at all, two ungranted
 * SECURITY DEFINER functions were enough for `anon` to set another user's role
 * to admin.
 *
 * WHAT THIS REPORTS, AND WHAT IT DELIBERATELY DOES NOT.
 *
 * Reachability is a fact from the catalog: who can execute it, what it runs as,
 * whether `search_path` is pinned, whether the grant was written by somebody or
 * is the default nobody revoked. All of that is reported.
 *
 * Whether the body enforces authorization correctly is NOT reported, and never
 * will be. That is static analysis over arbitrary PL/pgSQL and it would be
 * wrong quietly. The one body signal used here is presence, not correctness:
 * a function whose source never mentions `auth.uid`, `auth.jwt` or
 * `current_setting` anywhere is very unlikely to be enforcing anything. That is
 * a short list to hand a human, not a verdict.
 *
 * The boundary is deliberate and agreed with the author of UnitAutogen
 * (u/pgsql-dev2), which covers per-role function and trigger behaviour as pgTAP
 * tests. Surface enumeration and behavioural proof are different jobs.
 *
 * Credit: u/Far_Guess8176 and u/jaimittal91 on r/Supabase, the former off the
 * back of a production incident where a payment provider token was readable and
 * replaceable through the anon key.
 */

export interface DefinerFinding {
  /** Fully qualified, with identity arguments, so the fix is paste-ready. */
  signature: string;
  owner: string;
  /** True when the grant is the untouched Postgres default rather than a decision. */
  publicByDefault: boolean;
  reachableBy: string;
  searchPathPinned: boolean;
  /** Body mentions an identity source at all. False is the interesting case. */
  referencesIdentity: boolean;
  revoke: string;
}

export async function checkSecurityDefiners(
  c: PoolClient, schema: string,
): Promise<DefinerFinding[]> {
  const { rows } = await c.query(
    `select
       n.nspname || '.' || p.proname
         || '(' || pg_get_function_identity_arguments(p.oid) || ')' as signature,
       pg_get_userbyid(p.proowner)                                  as owner,
       (p.proacl is null)                                           as public_by_default,
       case
         when p.proacl is null then 'PUBLIC (default, never revoked)'
         else array_to_string(array(
                select g from unnest(p.proacl::text[]) g
                 where g like 'anon=%' or g like 'authenticated=%'), ', ')
       end                                                          as reachable_by,
       (p.proconfig is not null and exists (
          select 1 from unnest(p.proconfig) cfg where cfg like 'search\\_path=%'
        ))                                                          as search_path_pinned,
       (p.prosrc ~* '(auth\\.uid|auth\\.jwt|current_setting)')       as references_identity
     from pg_proc p
     join pg_namespace n on n.oid = p.pronamespace
     where p.prosecdef
       and n.nspname = $1
       and exists (
         select 1 from (values ('anon'), ('authenticated')) g(grantee)
          where exists (select 1 from pg_roles where rolname = g.grantee)
            and has_function_privilege(g.grantee, p.oid, 'EXECUTE')
       )
     order by (p.proacl is null) desc,
              (p.prosrc ~* '(auth\\.uid|auth\\.jwt|current_setting)'),
              p.proname`,
    [schema],
  );

  return rows.map((r) => ({
    signature: r.signature,
    owner: r.owner,
    publicByDefault: r.public_by_default,
    reachableBy: r.reachable_by,
    searchPathPinned: r.search_path_pinned,
    referencesIdentity: r.references_identity,
    // Full identity arguments: `revoke execute on function foo` fails on an
    // overloaded name, and that is the moment somebody gives up.
    revoke: `revoke execute on function ${r.signature} from public, anon, authenticated;`,
  }));
}
