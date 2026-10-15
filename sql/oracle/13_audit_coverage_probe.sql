--------------------------------------------------------------------------------
-- sopuli-dba : what can a service account read about unified audit policies,
--              and what does each way of enabling one record?   (v1)
--
-- #591 (H10). An unseen reset records whether the database would audit the
-- DBA's route to acting as the person: ALTER USER (a reset to a known value,
-- or a CONNECT THROUGH grant) and LOGON (the proxy logon that names the DBA).
-- 11_proxy_connect_probe.sql measured that route with one policy enabled for
-- everybody. This measures what the check has to read, and how BY and EXCEPT
-- lists change what is recorded:
--
--   AC0  the audit mode (V$OPTION 'Unified Auditing'), who holds a grant on
--        the two policy views, and what else the AUDIT_VIEWER role holds
--   AC1  as an account holding only CREATE SESSION and ALTER USER: V$OPTION,
--        AUDIT_UNIFIED_ENABLED_POLICIES and AUDIT_UNIFIED_POLICIES
--   AC2  whether SYSTEM can grant READ on the two views, then the same reads
--        after SYS grants READ on each of them to the account
--   AC3  what the two views show for each shape a check must classify: every
--        user, BY, EXCEPT, BY GRANTED ROLE, WHENEVER SUCCESSFUL, WHENEVER NOT
--        SUCCESSFUL, a condition, PRIVILEGES ALTER USER, and ACTIONS ALL; and
--        how many enabled rows the account sees with AC2's grants
--   AC4  one ACTIONS ALTER USER, LOGON policy, enabled in turn BY the person,
--        BY the DBA, EXCEPT the person and EXCEPT the DBA. In each round the
--        DBA grants itself CONNECT THROUGH, logs on as the person, and
--        revokes; then the person logs on. What the trail holds for each
--   AC5  the same route under PRIVILEGES ALTER USER, and under ACTIONS ALL,
--        each enabled for every user
--   AC6  a common ACTIONS ALTER USER, LOGON policy, enabled in CDB$ROOT for
--        every user: what the account sees of it in the PDB, and what it
--        records of the route, in the PDB's trail and in every container's.
--        As a control, a common account logs on to the PDB under it
--   AC7  READ on the two views, granted CONTAINER = ALL to a common account
--        by SYS in CDB$ROOT: does the common account read them in the PDB
--
-- This MEASURES and decides nothing. What a reset records is #591.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1,
-- as SYSTEM with AC2's grants as SYS, 2026-10-15 -- fourteen times, the last
-- two this file exactly as it stands (exit 0 both times, identical output).
-- Run 9 started from the state a run stopped in AC4a leaves behind: AC_ALL
-- enabled BY the person. AC3 to AC5 were identical in the twelve runs that
-- reached them. Run 1 stopped at AC2, where SYSTEM cannot grant; run 4 stopped at AC3
-- on a typing error. In runs 1 to 3 AC3 did not yet read the enabled rows as
-- the account, in runs 1 to 6 AC0 did not yet count AUDIT_VIEWER's grants, and
-- AC6 was added for run 9, read the root's trail from run 11, and had its
-- control from run 13, when AC7 was added. Untried on every other release.
-- 11.2 has no unified audit, so AC1 to AC7 do not apply there as written.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, 2026-10-15
--
--   AC0  Unified Auditing = TRUE: pure unified mode. READ on both policy views
--        is held by AUDIT_ADMIN and AUDIT_VIEWER only. PUBLIC holds READ on
--        V_$OPTION. AUDIT_VIEWER holds 34 object grants, UNIFIED_AUDIT_TRAIL
--        among them
--   AC1  V$OPTION is readable. Both views give ORA-00942
--   AC2  SYSTEM's GRANT READ gives ORA-01031. After SYS grants READ on each
--        view, both are readable: 0 enabled rows (FREEPDB1 enables no policy),
--        3268 policy rows
--   AC3  AUDIT_UNIFIED_ENABLED_POLICIES, one row per enablement:
--
--          POLICY     ENABLED_OPTION   ENTITY_NAME  ENTITY_TYPE  SUCCESS FAILURE
--          AC_ALL     BY USER          ALL USERS    USER         YES     YES
--          AC_BY      BY USER          AC_PERSON    USER         YES     YES
--          AC_EXCEPT  EXCEPT USER      AC_PERSON    USER         YES     YES
--          AC_ROLE_P  BY GRANTED ROLE  AC_ROLE      ROLE         YES     YES
--          AC_OK      BY USER          ALL USERS    USER         YES     NO
--          AC_NOTOK   BY USER          ALL USERS    USER         NO      YES
--          AC_COND    BY USER          ALL USERS    USER         YES     YES
--
--        AUDIT_UNIFIED_POLICIES: ACTIONS ALTER USER, LOGON gives two STANDARD
--        ACTION rows, ALTER USER and LOGON, and an XS ACTION row, UPDATE USER.
--        AUDIT_CONDITION and CONDITION_EVAL_OPT are NONE, except on AC_COND,
--        which carries the condition's text and SESSION. PRIVILEGES ALTER USER
--        is AUDIT_OPTION ALTER USER, type SYSTEM PRIVILEGE. ACTIONS ALL is
--        AUDIT_OPTION ALL, type STANDARD ACTION. The account sees all 7
--        enabled rows
--   AC4  what the trail holds for the route, by how the policy is enabled:
--
--          BY the person      the person's logon, and the proxy logon
--                             (DBUSERNAME the person, DBPROXY_USERNAME the
--                             DBA). Not the DBA's ALTER USER
--          BY the DBA         the DBA's logons and both ALTER USERs. Not the
--                             proxy logon
--          EXCEPT the person  as BY the DBA, plus a PROXY AUTHENTICATION row
--                             under the DBA
--          EXCEPT the DBA     as BY the person, plus a PROXY AUTHENTICATION
--                             row under the DBA
--
--   AC5  PRIVILEGES ALTER USER records the DBA's three ALTER USERs, the
--        IDENTIFIED BY one masked. ACTIONS ALL records both ALTER USERs, the
--        proxy logon and the person's logon, among everything else
--   AC6  the account sees the common policy in the PDB: BY USER, ALL USERS,
--        SUCCESS and FAILURE YES, and its rows with COMMON and INHERITED YES.
--        It records NONE of the route by the local accounts: no ALTER USER and
--        no logon, in the PDB's trail or in CDB_UNIFIED_AUDIT_TRAIL from the
--        root. The only row is PROXY AUTHENTICATION under the DBA, and that
--        row also appears in AC4 and AC5 under whatever policy is enabled. The
--        control's logon IS recorded: LOGON under C##AC_CSVC, in the PDB. So
--        the policy works, and does not apply to the local accounts
--   AC7  both grants succeed, and the common account reads both views in the
--        PDB: 0 enabled rows (none enabled then), 3291 policy rows
--
--   So a BY or EXCEPT list applies to the account that ISSUES the statement.
--   The person issues the logon and the DBA issues the ALTER USER, so a list
--   naming the person says nothing about the DBA's ALTER USER. A service
--   account needs READ on both views. SYS can grant it and SYSTEM cannot.
--   AUDIT_VIEWER holds both grants (AC0). A common policy looks like an
--   every-user policy from the PDB, records nothing of local accounts, and
--   records a common account's logon (AC6). A common service account takes
--   the grant with CONTAINER = ALL (AC7).
--
-- HOW TO RUN
--   As SYSTEM (or any account that can create users and audit policies), and
--   as SYS for AC2's grants, in the PDB; as SYS in CDB$ROOT for AC6's common
--   policy. Against the tier-1 stack, whose SYS
--   and SYSTEM password is the public one in test/compose.yaml, as it stands:
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < 13_audit_coverage_probe.sql
--
--   /nolog, and every CONNECT made from the script, so no password is ever in
--   argv (invariant 1). Against any other database, copy the file, edit the four
--   DEFINEs in the copy, run the copy and delete it, as 07 prescribes -- never
--   substitute them with sed, which puts the password in argv instead.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- WHENEVER SQLERROR is EXIT FAILURE throughout, and is relaxed to CONTINUE NONE
-- only around AC1's reads and SYSTEM's grant in AC2, which are meant to fail.
-- The drop-if-exists and clean-up blocks in the setup and the teardown swallow
-- their own errors and carry no secret.
--
-- THROWAWAY DATABASES ONLY. Creates and drops three local accounts, a common
-- one, a role, nine local audit policies and one common one, plants known passwords, and leaves rows in
-- UNIFIED_AUDIT_TRAIL. While AC5 runs, ACTIONS ALL audits every user.
--------------------------------------------------------------------------------
define svc      = FREEPDB1
define sys_conn = system/sopuli-test
define sysdba   = sys/sopuli-test
define cdb      = FREE

set lines 220 pages 200 feedback off verify off
whenever sqlerror exit failure
connect &sys_conn@&svc
col parameter for a20
col value for a8
col grantee for a14
col privilege for a10
col table_name for a32
col policy_name for a12
col enabled_option for a20
col entity_name for a12
col entity_type for a8
col success for a7
col failure for a7
col audit_option for a12
col audit_option_type for a18
col audit_condition for a36
col condition_eval_opt for a10
col dbusername for a12
col dbproxy_username for a16
col action_name for a22
col sql_text for a52

prompt === setup
connect &sysdba@&cdb as sysdba
begin execute immediate 'noaudit policy c##ac_common'; exception when others then null; end;
/
begin execute immediate 'drop audit policy c##ac_common'; exception when others then null; end;
/
begin execute immediate 'drop user c##ac_csvc cascade'; exception when others then null; end;
/
create user c##ac_csvc identified by "AcCsvcPw_2209" container = all;
grant create session to c##ac_csvc container = all;
connect &sys_conn@&svc
-- Every enablement is undone with the clause it was made with: a plain NOAUDIT
-- does not undo a BY list or a role, and DROP AUDIT POLICY then fails. Each
-- statement swallows its own error, so a run stopped half way does not stop
-- the next one here.
begin
  for p in (select policy_name, enabled_option, entity_name
              from audit_unified_enabled_policies
             where policy_name like 'AC\_%' escape '\') loop
    begin
      execute immediate 'noaudit policy ' || p.policy_name ||
        case
          when p.enabled_option = 'BY USER' and p.entity_name <> 'ALL USERS'
            then ' by ' || p.entity_name
          when p.enabled_option = 'BY GRANTED ROLE'
            then ' by users with granted roles ' || p.entity_name
        end;
    exception when others then null;
    end;
  end loop;
  for p in (select distinct policy_name from audit_unified_policies
             where policy_name like 'AC\_%' escape '\') loop
    begin
      execute immediate 'drop audit policy ' || p.policy_name;
    exception when others then null;
    end;
  end loop;
end;
/
begin execute immediate 'drop user ac_svc cascade'; exception when others then null; end;
/
begin execute immediate 'drop user ac_dba cascade'; exception when others then null; end;
/
begin execute immediate 'drop user ac_person cascade'; exception when others then null; end;
/
begin execute immediate 'drop role ac_role'; exception when others then null; end;
/
create user ac_svc    identified by "AcSvcPw_6620";
create user ac_dba    identified by "AcDbaPw_3318";
create user ac_person identified by "AcPersonPw_9045";
create role ac_role;
grant create session to ac_svc, ac_dba, ac_person;
grant alter user to ac_svc, ac_dba;

prompt === AC0: the audit mode, and who can read the policy views
select parameter, value from v$option where parameter = 'Unified Auditing';
select grantee, privilege, table_name from dba_tab_privs
 where owner = 'SYS'
   and table_name in ('AUDIT_UNIFIED_ENABLED_POLICIES', 'AUDIT_UNIFIED_POLICIES', 'V_$OPTION')
 order by table_name, grantee;
-- What the AUDIT_VIEWER role holds besides the two views, which is what makes
-- the two READ grants the narrower choice.
select count(*) as audit_viewer_grants,
       count(case when table_name = 'UNIFIED_AUDIT_TRAIL' then 1 end) as reads_the_trail
  from dba_tab_privs where grantee = 'AUDIT_VIEWER';

prompt === AC1: CREATE SESSION + ALTER USER only -> V$OPTION, then the two views
connect ac_svc/"AcSvcPw_6620"@&svc
select value from v$option where parameter = 'Unified Auditing';
whenever sqlerror continue none
select count(*) from audit_unified_enabled_policies;
select count(*) from audit_unified_policies;
whenever sqlerror exit failure

prompt === AC2: READ on each view, granted to the account
-- SYSTEM cannot grant on these two views (ORA-01031), so the grant is made as
-- SYS, and the attempt as SYSTEM is kept as a result.
connect &sys_conn@&svc
whenever sqlerror continue none
grant read on sys.audit_unified_enabled_policies to ac_svc;
whenever sqlerror exit failure
connect &sysdba@&svc as sysdba
grant read on sys.audit_unified_enabled_policies to ac_svc;
grant read on sys.audit_unified_policies to ac_svc;
connect ac_svc/"AcSvcPw_6620"@&svc
select count(*) as enabled_rows from audit_unified_enabled_policies;
select count(*) as policy_rows from audit_unified_policies;

prompt === AC3: what the views show for each shape
connect &sys_conn@&svc
create audit policy ac_all    actions alter user, logon;
create audit policy ac_by     actions alter user, logon;
create audit policy ac_except actions alter user, logon;
create audit policy ac_role_p actions alter user, logon;
create audit policy ac_ok     actions alter user, logon;
create audit policy ac_notok  actions alter user, logon;
create audit policy ac_cond   actions alter user, logon
  when 'sys_context(''userenv'', ''ip_address'') = ''192.0.2.1''' evaluate per session;
create audit policy ac_priv   privileges alter user;
create audit policy ac_every  actions all;
audit policy ac_all;
audit policy ac_by     by ac_person;
audit policy ac_except except ac_person;
audit policy ac_role_p by users with granted roles ac_role;
audit policy ac_ok     whenever successful;
audit policy ac_notok  whenever not successful;
audit policy ac_cond;
select policy_name, enabled_option, entity_name, entity_type, success, failure
  from audit_unified_enabled_policies
 where policy_name like 'AC\_%' escape '\'
 order by policy_name, entity_name;
select policy_name, audit_option, audit_option_type, audit_condition, condition_eval_opt
  from audit_unified_policies
 where policy_name like 'AC\_%' escape '\'
 order by policy_name, audit_option;
-- The same rows as the service account, with AC2's grants: a grant that showed
-- it nothing enabled would read as "no policy" everywhere.
connect ac_svc/"AcSvcPw_6620"@&svc
select count(*) as enabled_rows_seen_by_svc from audit_unified_enabled_policies
 where policy_name like 'AC\_%' escape '\';
connect &sys_conn@&svc
noaudit policy ac_all;
noaudit policy ac_by     by ac_person;
noaudit policy ac_except;
noaudit policy ac_role_p by users with granted roles ac_role;
noaudit policy ac_ok;
noaudit policy ac_notok;
noaudit policy ac_cond;

prompt === AC4: the route under BY and EXCEPT
-- One round per way of enabling ac_all. Each round is bounded by its own
-- start time, because UNIFIED_AUDIT_TRAIL outlives the accounts and the
-- policies, and a query by name alone would read earlier rounds as well.
column t0 new_value t0 noprint

prompt --- AC4a: BY the person
audit policy ac_all by ac_person;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect ac_person/"AcPersonPw_9045"@&svc
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and dbusername like 'AC\_%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_all by ac_person;

prompt --- AC4b: BY the DBA
audit policy ac_all by ac_dba;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect ac_person/"AcPersonPw_9045"@&svc
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and dbusername like 'AC\_%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_all by ac_dba;

prompt --- AC4c: EXCEPT the person
audit policy ac_all except ac_person;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect ac_person/"AcPersonPw_9045"@&svc
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and dbusername like 'AC\_%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_all;

prompt --- AC4d: EXCEPT the DBA
audit policy ac_all except ac_dba;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect ac_person/"AcPersonPw_9045"@&svc
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and dbusername like 'AC\_%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_all;

prompt === AC5: the route under PRIVILEGES ALTER USER, then under ACTIONS ALL
prompt --- AC5a: PRIVILEGES ALTER USER, every user
audit policy ac_priv;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
alter user ac_person identified by "AcPersonPw_9046";
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and dbusername like 'AC\_%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_priv;

prompt --- AC5b: ACTIONS ALL, every user
audit policy ac_every;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect ac_person/"AcPersonPw_9046"@&svc
connect &sys_conn@&svc
noaudit policy ac_every;
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and dbusername like 'AC\_%' escape '\'
 order by event_timestamp_utc;

prompt === AC6: a common policy, enabled in CDB$ROOT
connect &sysdba@&cdb as sysdba
create audit policy c##ac_common actions alter user, logon container = all;
audit policy c##ac_common;
connect ac_svc/"AcSvcPw_6620"@&svc
select policy_name, enabled_option, entity_name, success, failure
  from audit_unified_enabled_policies where policy_name like 'C##AC\_%' escape '\';
select policy_name, audit_option, audit_option_type, common, inherited
  from audit_unified_policies where policy_name like 'C##AC\_%' escape '\'
 order by audit_option;
connect &sys_conn@&svc
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
-- The control: a common account logs on to the PDB under the same policy. A
-- policy that records this and not the local accounts above is working, and
-- is not applied to local accounts.
connect c##ac_csvc/"AcCsvcPw_2209"@&svc
connect &sys_conn@&svc
select dbusername, dbproxy_username, action_name, substr(sql_text, 1, 52) as sql_text
  from unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and (dbusername like 'AC\_%' escape '\' or dbusername like 'C##AC\_%' escape '\')
 order by event_timestamp_utc;
-- Every container's trail, from the root, in case the records went there.
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and (dbusername like 'AC\_%' escape '\' or dbusername like 'C##AC\_%' escape '\')
 order by event_timestamp_utc;
noaudit policy c##ac_common;
drop audit policy c##ac_common;

prompt === AC7: READ on the two views for a common account, granted CONTAINER = ALL
-- As SYS in the root. Whether the grant reaches the PDB is the question, so a
-- failure here is a result and does not stop the run.
whenever sqlerror continue none
grant read on sys.audit_unified_enabled_policies to c##ac_csvc container = all;
grant read on sys.audit_unified_policies to c##ac_csvc container = all;
connect c##ac_csvc/"AcCsvcPw_2209"@&svc
select count(*) as enabled_rows from audit_unified_enabled_policies;
select count(*) as policy_rows from audit_unified_policies;
whenever sqlerror exit failure

prompt === teardown
connect &sys_conn@&svc
-- The same block as the setup's. The file is piped to SQL*Plus on stdin, so
-- it cannot load a shared file with @@; change both copies together.
-- Every enablement is undone with the clause it was made with: a plain NOAUDIT
-- does not undo a BY list or a role, and DROP AUDIT POLICY then fails. Each
-- statement swallows its own error, so a run stopped half way does not stop
-- the next one here.
begin
  for p in (select policy_name, enabled_option, entity_name
              from audit_unified_enabled_policies
             where policy_name like 'AC\_%' escape '\') loop
    begin
      execute immediate 'noaudit policy ' || p.policy_name ||
        case
          when p.enabled_option = 'BY USER' and p.entity_name <> 'ALL USERS'
            then ' by ' || p.entity_name
          when p.enabled_option = 'BY GRANTED ROLE'
            then ' by users with granted roles ' || p.entity_name
        end;
    exception when others then null;
    end;
  end loop;
  for p in (select distinct policy_name from audit_unified_policies
             where policy_name like 'AC\_%' escape '\') loop
    begin
      execute immediate 'drop audit policy ' || p.policy_name;
    exception when others then null;
    end;
  end loop;
end;
/
drop user ac_svc cascade;
drop user ac_dba cascade;
drop user ac_person cascade;
drop role ac_role;
connect &sysdba@&cdb as sysdba
drop user c##ac_csvc cascade;
connect &sys_conn@&svc
select count(*) as leftover_users from dba_users where username like 'AC\_%' escape '\';
select count(*) as leftover_policies from audit_unified_policies
 where policy_name like 'AC\_%' escape '\';
exit
