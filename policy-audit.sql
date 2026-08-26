-- Find tables where UPDATE or DELETE is effectively unrestricted.
--
-- Grouped by table + command on purpose. Postgres ORs all PERMISSIVE policies
-- for a given command together, so one `using (true)` alongside a perfectly
-- scoped policy leaves the table wide open -- the loose one wins. Checking
-- policies one row at a time will show you the good policy and you'll move on.
--
-- Read-only. Safe on production.
select
  p.tablename,
  p.cmd,
  count(*)                                              as policies_on_cmd,
  bool_or(p.qual in ('true', '(true)'))                 as has_permissive,
  string_agg(p.policyname || ': ' || coalesce(p.qual, 'null'),
             '  |  ' order by p.policyname)             as policies,
  case
    when bool_or(p.qual in ('true', '(true)')) and count(*) > 1
      then 'WIDE OPEN — a permissive policy ORs past the scoped one'
    when bool_or(p.qual in ('true', '(true)'))
      then 'WIDE OPEN — applies to every row'
    else 'scoped'
  end                                                   as verdict
from pg_policies p
where p.schemaname = 'public'
  and p.cmd in ('UPDATE', 'DELETE', 'ALL')
  and p.permissive = 'PERMISSIVE'
group by p.tablename, p.cmd
order by bool_or(p.qual in ('true', '(true)')) desc, p.tablename, p.cmd;
