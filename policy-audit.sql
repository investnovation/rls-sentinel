-- Find tables where SELECT is scoped but UPDATE or DELETE is not.
-- Read-only. Safe on production.
select
  p.tablename,
  p.cmd,
  p.qual                                   as using_expression,
  case
    when p.qual in ('true', '(true)') then 'PERMISSIVE — applies to every row'
    else 'scoped'
  end                                      as verdict
from pg_policies p
where p.schemaname = 'public'
  and p.cmd in ('UPDATE', 'DELETE', 'ALL')
order by
  (p.qual in ('true', '(true)')) desc,
  p.tablename, p.cmd;
