--------------------------------------------------------------------------------
-- sopuli-dba : can ALTER USER alone connect as somebody else?   (v1)
--
-- #459 and #496. The threat model proposed on both says a DBA who can reset a
-- personal account's password can also connect AS that person through Oracle
-- proxy authentication -- `ALTER USER person GRANT CONNECT THROUGH dba` --
-- needing only the ALTER USER system privilege, which is the one sopuli's
-- service account is built around (02-oracle-privileges.md sec.2). That came
-- from Oracle's documentation. This is the run that measures it, and measures
-- what the route leaves behind, since "whose name is left behind" is the whole
-- of the proposed principle:
--
--   C1   CONTROL: an account WITHOUT ALTER USER issues the grant. Must give
--        ORA-01031, or PX1 says nothing about ALTER USER
--   PX1  an account holding CREATE SESSION and ALTER USER and nothing else
--        grants CONNECT THROUGH on the person's account to itself
--   PX2  it connects as the person with its OWN password -- what USER,
--        SESSION_USER, PROXY_USER and AUTHENTICATED_IDENTITY report
--   PX3  DBA_PROXIES while the grant exists
--   PX4  the same account revokes the grant -- does DBA_PROXIES keep anything
--   PX5  unified audit for PX1..PX4, with the audit configuration as found;
--        read after the revoke, so it covers all four
--   PX6  PX1..PX4 again under a probe-local LOGON + ALTER USER policy
--
-- This MEASURES and decides nothing. Whether the principle is accepted, and
-- with what condition, is #459 / #496.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1,
-- as SYSTEM, 2026-10-01 -- seven times, the last two this file exactly as it
-- stands (via /nolog, exit 0 both times). C1 and PX1..PX4 identical in all
-- seven. PX5 and PX6 as reported are from the last two: in runs 1 and 2 the
-- audit queries were not scoped to the run and read earlier runs' rows (the
-- &t0/&t1 bounds are the fix), and in runs 1 to 5 PX5 was read BEFORE the
-- revoke, so it could not speak for it (review on #589; it now follows PX4).
-- One further attempt stalled at PX6 and was stopped; its objects were gone
-- when checked. Untried on every other release. 11.2 has no unified audit,
-- so PX5 and PX6 do not apply there as written.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, as SYSTEM, 2026-10-01
--
--   C1   ORA-01031: insufficient privileges
--   PX1  succeeds
--   PX2  USER = SESSION_USER = PX_PERSON; PROXY_USER = PX_DBA;
--        AUTHENTICATED_IDENTITY = PX_DBA. The person's password is never used
--   PX3  PX_DBA -> PX_PERSON, AUTHENTICATION NO,
--        "PROXY MAY ACTIVATE ALL CLIENT ROLES"
--   PX4  succeeds; DBA_PROXIES has no row for PX_PERSON afterwards
--   PX5  NO ROWS. FREEPDB1 has no unified audit policy enabled, and the grant,
--        the proxy logon and the revoke leave nothing in UNIFIED_AUDIT_TRAIL
--   PX6  with the policy, in order:
--
--          DBUSERNAME  DBPROXY_USERNAME  ACTION_NAME           SQL_TEXT
--          PX_DBA                        LOGON
--          PX_DBA                        ALTER USER            ... grant connect through px_dba
--          PX_DBA                        PROXY AUTHENTICATION
--          PX_PERSON   PX_DBA            LOGON
--          PX_DBA                        LOGON
--          PX_DBA                        ALTER USER            ... revoke connect through px_dba
--
--   So the route is real and needs nothing sopuli's service account lacks
--   (PX1, PX2). The session itself names the DBA (PX2), but the only DURABLE
--   trace is the audit trail: the same privilege that makes the grant removes
--   it from DBA_PROXIES (PX4), and with no policy recording ALTER USER and
--   logons there is no audit trail to speak of (PX5). "The DBA's name is left
--   behind" holds where such a policy exists (PX6), and not otherwise.
--
--   Not measured: whether an account that also holds AUDIT SYSTEM can disable
--   the policy first. The probe's account does not hold it.
--
-- HOW TO RUN
--   As SYSTEM (or any account that can create users and audit policies), in
--   the PDB. Against the tier-1 stack, whose SYSTEM password is the public one
--   in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 11_proxy_connect_probe.sql
--
--   /nolog, and every CONNECT made from the script, so no password is ever in
--   argv (invariant 1). Against any other database, copy the file, edit the two
--   DEFINEs in the copy, run the copy and delete it, as 07 prescribes -- never
--   substitute them with sed, which puts the password in argv instead.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is EXIT FAILURE throughout, a failed CONNECT included
-- (checked: ORA-01017 exits 1), and is relaxed to CONTINUE NONE only around C1,
-- the one statement meant to fail. The setup's drop-if-exists blocks swallow
-- their own errors and carry no secret.
--
-- THROWAWAY DATABASES ONLY. Creates and drops three accounts and an audit
-- policy, plants known passwords, and leaves rows in UNIFIED_AUDIT_TRAIL.
--------------------------------------------------------------------------------
define svc      = FREEPDB1
define sys_conn = system/sopuli-test

set lines 220 pages 200 feedback off verify off
whenever sqlerror exit failure
connect &sys_conn@&svc
col username for a14
col proxy for a14
col client for a14
col dbusername for a14
col dbproxy_username for a16
col action_name for a14
col sql_text for a60
col authorization_constraint for a40
col authentication for a6

prompt === setup
begin execute immediate 'drop user px_dba cascade'; exception when others then null; end;
/
begin execute immediate 'drop user px_nopriv cascade'; exception when others then null; end;
/
begin execute immediate 'drop user px_person cascade'; exception when others then null; end;
/
begin execute immediate 'noaudit policy px_pol'; exception when others then null; end;
/
begin execute immediate 'drop audit policy px_pol'; exception when others then null; end;
/
create user px_dba    identified by "PxDbaPw_9137";
create user px_nopriv identified by "PxNoPw_4402";
create user px_person identified by "PxPersonPw_7261";
grant create session to px_dba, px_nopriv, px_person;
grant alter user to px_dba;
select grantee, privilege from dba_sys_privs where grantee like 'PX\_%' escape '\' order by 1,2;
-- Lower bound for PX5: UNIFIED_AUDIT_TRAIL outlives the dropped accounts, so a
-- query by name alone reads every earlier run as well.
column t0 new_value t0 noprint
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
prompt run starts &t0 UTC

prompt === C1: no ALTER USER -> expect ORA-01031
connect px_nopriv/"PxNoPw_4402"@&svc
whenever sqlerror continue none
alter user px_person grant connect through px_nopriv;
whenever sqlerror exit failure

prompt === PX1: ALTER USER only -> grant CONNECT THROUGH
connect px_dba/"PxDbaPw_9137"@&svc
alter user px_person grant connect through px_dba;

prompt === PX2: connect as the person through px_dba, without the person's password
connect px_dba[px_person]/"PxDbaPw_9137"@&svc
select user as username,
       sys_context('userenv','session_user') as session_user,
       sys_context('userenv','proxy_user')   as proxy,
       sys_context('userenv','authenticated_identity') as client
  from dual;

prompt === PX3: DBA_PROXIES
connect &sys_conn@&svc
select proxy, client, authentication, authorization_constraint
  from dba_proxies where client = 'PX_PERSON';

prompt === PX4: revoke by the same account
connect px_dba/"PxDbaPw_9137"@&svc
alter user px_person revoke connect through px_dba;
connect &sys_conn@&svc
select count(*) as proxies_after_revoke from dba_proxies where client = 'PX_PERSON';

prompt === PX5: unified audit for PX1..PX4, audit configuration as found
select policy_name from audit_unified_enabled_policies;
select dbusername, dbproxy_username, action_name, return_code
  from unified_audit_trail
 where (dbusername like 'PX\_%' escape '\' or dbproxy_username like 'PX\_%' escape '\')
   and event_timestamp_utc >= to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
 order by event_timestamp_utc;

prompt === PX6: PX1..PX4 again under a LOGON + ALTER USER policy
column t1 new_value t1 noprint
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t1 from dual;
create audit policy px_pol actions logon, alter user;
audit policy px_pol;
connect px_dba/"PxDbaPw_9137"@&svc
alter user px_person grant connect through px_dba;
connect px_dba[px_person]/"PxDbaPw_9137"@&svc
select user as username, sys_context('userenv','proxy_user') as proxy from dual;
connect px_dba/"PxDbaPw_9137"@&svc
alter user px_person revoke connect through px_dba;
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, return_code,
       substr(sql_text,1,60) as sql_text
  from unified_audit_trail
 where unified_audit_policies like '%PX_POL%'
   and (dbusername like 'PX\_%' escape '\' or dbproxy_username like 'PX\_%' escape '\')
   and event_timestamp_utc >= to_timestamp('&t1','YYYY-MM-DD HH24:MI:SS.FF6')
 order by event_timestamp_utc;

prompt === teardown
noaudit policy px_pol;
drop audit policy px_pol;
drop user px_dba cascade;
drop user px_nopriv cascade;
drop user px_person cascade;
select count(*) as leftover_users from dba_users where username like 'PX\_%' escape '\';
exit
