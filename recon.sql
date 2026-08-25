-- RLS Sentinel — read-only schema recon.
-- Pure catalog SELECTs. Writes nothing. Safe on production.
select
  c.relname                                        as table_name,
  c.relrowsecurity                                 as rls_on,
  count(distinct p.polname)                        as policies,
  (select string_agg(a.attname, ', ' order by a.attname)
     from pg_attribute a
    where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
      and a.attname in ('user_id','owner_id','tenant_id','profile_id',
                        'account_id','created_by','author_id',
                        'organization_id','org_id'))               as owner_col,
  (select string_agg(distinct rn.nspname || '.' || rc.relname, ', ')
     from pg_constraint con
     join pg_class rc     on rc.oid = con.confrelid
     join pg_namespace rn on rn.oid = rc.relnamespace
    where con.conrelid = c.oid and con.contype = 'f')              as fks_to,
  c.reltuples::bigint                              as est_rows
from pg_class c
join pg_namespace n  on n.oid = c.relnamespace
left join pg_policy p on p.polrelid = c.oid
where n.nspname = 'public' and c.relkind in ('r','p')
group by c.relname, c.relrowsecurity, c.oid, c.reltuples
order by (c.relrowsecurity is false) desc, c.relname;
