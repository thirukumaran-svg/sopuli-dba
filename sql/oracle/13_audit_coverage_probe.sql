--------------------------------------------------------------------------------
-- sopuli-dba : what can a service account read about unified audit policies,
--              and what does each way of enabling one record?   (v2)
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
--   AC8  01_audit_policy.sql's two policies, created in three places: in
--        CDB$ROOT with no CONTAINER clause, in CDB$ROOT with CONTAINER = ALL,
--        and in the PDB. What each records of a local DBA's ALTER USER and
--        proxy logon in the PDB, and of the common service account's ALTER
--        USER and failed logons
--   AC9  a common person. The common service account resets it in the root,
--        and a common DBA logs on as it in the root and in the PDB. The logon
--        policy is enabled BY the person, in the root with and without
--        CONTAINER = ALL, and in the PDB
--   AC10 whether a common policy and a policy in the PDB may have one name
--
-- This MEASURES and decides nothing. What a reset records is #591.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1
-- and CDB$ROOT, as SYSTEM, and as SYS for the grants and the root. AC0 to AC7
-- were run fourteen times on 2026-10-15 while the file grew, and AC3 to AC5
-- were identical in the twelve runs that reached them. One of those runs
-- started from the state a run stopped in AC4a leaves behind, AC_ALL enabled
-- BY the person, with the same result. The file as it stands was run three
-- times on 2026-10-17, from a container with no other policy enabled: exit 0
-- and the same rows each time, and AC0 to AC7 as on 2026-10-15. Untried on
-- every other release. 11.2 has neither unified auditing nor containers, so
-- no section applies there as written.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, 2026-10-15
--
--   AC0  Unified Auditing = TRUE: pure unified mode. READ on both policy views
--        is held by AUDIT_ADMIN and AUDIT_VIEWER only. PUBLIC holds READ on
--        V_$OPTION. AUDIT_VIEWER holds 34 object grants, UNIFIED_AUDIT_TRAIL
--        among them. No policy is enabled at the start, in the PDB or in the
--        root: both reads return no rows, which prints nothing
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
--   AC8  what is recorded, by where the two policies are created:
--
--          CDB$ROOT, no clause  the root's failed logon only. NOTHING in the
--                               PDB, not even the service account's ALTER
--                               USER. SYSTEM sees neither policy enabled in
--                               the PDB
--          CONTAINER = ALL      in the PDB, the service account's ALTER USER
--                               and failed logon; in the root, its failed
--                               logon. Not the local DBA's ALTER USERs
--          the PDB              in the PDB, the local DBA's three ALTER USERs,
--                               the service account's ALTER USER and its
--                               failed logon
--
--        No round records the proxy logon: the logon policy records only the
--        service account's failures, as the script enables it
--   AC9  the root's CONNECT THROUGH grant works in the PDB: the proxy logon
--        there succeeds with no grant made in the PDB. The service account's
--        ALTER USER of the common person is recorded in the root in every
--        round, by a policy common or not. The proxy logon, DBPROXY_USERNAME
--        C##AC_CDBA, is recorded:
--
--          CDB$ROOT, CONTAINER = ALL  in the root and in the PDB
--          the PDB                    in the PDB only
--          CDB$ROOT, no clause        in the root only
--
--        In AC9c, AC_PC_POL is still enabled beside AC_PR_POL. The ALTER USER
--        gives one row, which names both policies: one event is one row,
--        whatever number of policies match it
--   AC10 both CREATEs succeed, in either order. The PDB's
--        AUDIT_UNIFIED_POLICIES then has the name twice, COMMON YES and NO
--
--   So a BY or EXCEPT list applies to the account that ISSUES the statement.
--   The person issues the logon and the DBA issues the ALTER USER, so a list
--   naming the person says nothing about the DBA's ALTER USER. A service
--   account needs READ on both views. SYS can grant it and SYSTEM cannot.
--   AUDIT_VIEWER holds both grants (AC0). A common policy looks like an
--   every-user policy from the PDB, records nothing of local accounts, and
--   records a common account's logon (AC6). A common service account takes
--   the grant with CONTAINER = ALL (AC7). A policy created in CDB$ROOT with no
--   CONTAINER clause records nothing in a PDB. A common policy records common
--   accounts in every container, and a PDB's own policy records every account
--   in that PDB, common ones too (AC8). AC9 resets a common account in the
--   root, and a policy in the root records that, common or not. A reset of a
--   common account made from a PDB is not tried. A name alone does not tell a
--   common policy from a PDB's own (AC10).
--
-- HOW TO RUN
--   As SYSTEM (or any account that can create users and audit policies), and
--   as SYS for AC2's grants, in the PDB; as SYS in CDB$ROOT for the common
--   accounts and the root's policies. Against the tier-1 stack, whose SYS
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
-- WHENEVER SQLERROR is EXIT FAILURE throughout. It is relaxed to CONTINUE NONE
-- around AC1's reads, SYSTEM's grant in AC2, AC8's failed logons and AC10's
-- CREATEs, which are meant to fail or are the question. AC7's grants are a
-- question too. The drop-if-exists and clean-up blocks in the setup and the
-- teardown swallow their own errors and carry no secret.
--
-- THROWAWAY DATABASES ONLY. Creates and drops local and common accounts, a
-- role, and audit policies in the PDB and in the root, plants known passwords,
-- and leaves rows in UNIFIED_AUDIT_TRAIL. While AC5 runs, ACTIONS ALL audits
-- every user.
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
-- The root's policies: AC6's, AC8's, AC9's and AC10's. They are named AC_ or
-- C##AC_. The PDB's loop below, without its role branch, because no root
-- policy is enabled for a role. It runs in the root first, so the PDB's loop
-- does not meet a common policy it cannot drop. A plain NOAUDIT undoes an
-- EXCEPT list, as AC4c and AC4d do, so neither loop needs a branch for it.
-- The setup and the teardown each run this loop and the PDB's. The file is
-- piped to SQL*Plus on stdin, so it cannot load a shared file with @@; change
-- all four copies together.
begin
  for p in (select policy_name, enabled_option, entity_name
              from audit_unified_enabled_policies
             where policy_name like 'AC\_%' escape '\'
                or policy_name like 'C##AC\_%' escape '\') loop
    begin
      execute immediate 'noaudit policy ' || p.policy_name ||
        case
          when p.enabled_option = 'BY USER' and p.entity_name <> 'ALL USERS'
            then ' by ' || p.entity_name
        end;
    exception when others then null;
    end;
  end loop;
  for p in (select distinct policy_name from audit_unified_policies
             where policy_name like 'AC\_%' escape '\'
                or policy_name like 'C##AC\_%' escape '\') loop
    begin
      execute immediate 'drop audit policy ' || p.policy_name;
    exception when others then null;
    end;
  end loop;
end;
/
begin execute immediate 'drop user c##ac_csvc cascade'; exception when others then null; end;
/
begin execute immediate 'drop user c##ac_cperson cascade'; exception when others then null; end;
/
begin execute immediate 'drop user c##ac_cdba cascade'; exception when others then null; end;
/
create user c##ac_csvc    identified by "AcCsvcPw_2209"    container = all;
create user c##ac_cperson identified by "AcCpersonPw_5172" container = all;
create user c##ac_cdba    identified by "AcCdbaPw_8841"    container = all;
grant create session to c##ac_csvc, c##ac_cperson, c##ac_cdba container = all;
grant alter user to c##ac_csvc container = all;
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
-- What is enabled before the run, in the PDB and in the root. Another policy
-- adds its records to every round, so the results hold for this start only.
-- The probe does not disable another policy: that would change the estate
-- it runs on.
col enabled_at_start for a28
col enabled_in_root for a28
select policy_name as enabled_at_start, entity_name from audit_unified_enabled_policies
 order by policy_name, entity_name;
connect &sysdba@&cdb as sysdba
select policy_name as enabled_in_root, entity_name from audit_unified_enabled_policies
 order by policy_name, entity_name;
connect &sys_conn@&svc
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

prompt === AC8: 01_audit_policy.sql's two policies, in three places
-- The script's statements, under other names: ALTER USER, CREATE USER and DROP
-- USER for every user, and failed logons BY the common service account. Each
-- round runs the same route. In the PDB: the local DBA resets the person, the
-- common service account resets the person, the DBA logs on as the person, and
-- the service account fails a logon. In the root: the service account fails a
-- logon. Then the root reads every container's trail.
col unified_audit_policies for a28
col dbusername for a14
connect &sysdba@&cdb as sysdba
create audit policy ac_sr_pol  actions alter user, create user, drop user;
create audit policy ac_sr_logon actions logon;
create audit policy ac_sc_pol   actions alter user, create user, drop user container = all;
create audit policy ac_sc_logon actions logon container = all;
connect &sys_conn@&svc
create audit policy ac_sp_pol   actions alter user, create user, drop user;
create audit policy ac_sp_logon actions logon;

prompt --- AC8a: in CDB$ROOT, no CONTAINER clause, as the script runs on a COMMON install
connect &sysdba@&cdb as sysdba
audit policy ac_sr_pol;
audit policy ac_sr_logon by c##ac_csvc whenever not successful;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect &sys_conn@&svc
select policy_name, entity_name, success, failure from audit_unified_enabled_policies
 where policy_name like 'AC\_S%' escape '\' order by policy_name;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person identified by "AcPersonPw_9047";
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect c##ac_csvc/"AcCsvcPw_2209"@&svc
alter user ac_person identified by "AcPersonPw_9048";
whenever sqlerror continue none
connect c##ac_csvc/"NotThePassword_1"@&svc
connect c##ac_csvc/"NotThePassword_1"@&cdb
whenever sqlerror exit failure
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name, return_code, unified_audit_policies
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and unified_audit_policies like '%AC\_S%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_sr_pol;
noaudit policy ac_sr_logon by c##ac_csvc;

prompt --- AC8b: in CDB$ROOT, CONTAINER = ALL
audit policy ac_sc_pol;
audit policy ac_sc_logon by c##ac_csvc whenever not successful;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect &sys_conn@&svc
select policy_name, entity_name, success, failure from audit_unified_enabled_policies
 where policy_name like 'AC\_S%' escape '\' order by policy_name;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person identified by "AcPersonPw_9049";
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect c##ac_csvc/"AcCsvcPw_2209"@&svc
alter user ac_person identified by "AcPersonPw_9050";
whenever sqlerror continue none
connect c##ac_csvc/"NotThePassword_1"@&svc
connect c##ac_csvc/"NotThePassword_1"@&cdb
whenever sqlerror exit failure
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name, return_code, unified_audit_policies
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and unified_audit_policies like '%AC\_S%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_sc_pol;
noaudit policy ac_sc_logon by c##ac_csvc;

prompt --- AC8c: in the PDB, no CONTAINER clause, as the script runs on a PDB install
connect &sys_conn@&svc
audit policy ac_sp_pol;
audit policy ac_sp_logon by c##ac_csvc whenever not successful;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
select policy_name, entity_name, success, failure from audit_unified_enabled_policies
 where policy_name like 'AC\_S%' escape '\' order by policy_name;
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person identified by "AcPersonPw_9051";
alter user ac_person grant connect through ac_dba;
connect ac_dba[ac_person]/"AcDbaPw_3318"@&svc
connect ac_dba/"AcDbaPw_3318"@&svc
alter user ac_person revoke connect through ac_dba;
connect c##ac_csvc/"AcCsvcPw_2209"@&svc
alter user ac_person identified by "AcPersonPw_9052";
whenever sqlerror continue none
connect c##ac_csvc/"NotThePassword_1"@&svc
connect c##ac_csvc/"NotThePassword_1"@&cdb
whenever sqlerror exit failure
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name, return_code, unified_audit_policies
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and unified_audit_policies like '%AC\_S%' escape '\'
 order by event_timestamp_utc;
connect &sys_conn@&svc
noaudit policy ac_sp_pol;
noaudit policy ac_sp_logon by c##ac_csvc;

prompt === AC9: a common person
-- A common account's password is changed in the root, and its proxy logon can
-- land in any container. The proxy grant is made in the root only. Each round:
-- in the root, the service account resets the person; the DBA logs on as the
-- person in the root, then in the PDB.
connect &sysdba@&cdb as sysdba
alter user c##ac_cperson grant connect through c##ac_cdba;
create audit policy ac_pc_pol   actions alter user, create user, drop user container = all;
create audit policy ac_pc_logon actions logon container = all;
create audit policy ac_pr_pol   actions alter user, create user, drop user;
create audit policy ac_pr_logon actions logon;
connect &sys_conn@&svc
create audit policy ac_pp_logon actions logon;

prompt --- AC9 proxy: does the root's grant reach the PDB?
-- A question, so a failure is a result. The rounds below log on through this
-- grant in the PDB, so on a release where it fails they stop the run there.
whenever sqlerror continue none
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&svc
select user as dbusername, sys_context('userenv', 'proxy_user') as dbproxy_username from dual;
whenever sqlerror exit failure

prompt --- AC9a: both policies in CDB$ROOT, CONTAINER = ALL
connect &sysdba@&cdb as sysdba
audit policy ac_pc_pol;
audit policy ac_pc_logon by c##ac_cperson whenever successful;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect c##ac_csvc/"AcCsvcPw_2209"@&cdb
alter user c##ac_cperson identified by "AcCpersonPw_5173" container = all;
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&cdb
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&svc
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name, return_code, unified_audit_policies
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and unified_audit_policies like '%AC\_P%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_pc_logon by c##ac_cperson;

prompt --- AC9b: ALTER USER common, LOGON in the PDB
connect &sys_conn@&svc
audit policy ac_pp_logon by c##ac_cperson whenever successful;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect c##ac_csvc/"AcCsvcPw_2209"@&cdb
alter user c##ac_cperson identified by "AcCpersonPw_5174" container = all;
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&cdb
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&svc
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name, return_code, unified_audit_policies
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and unified_audit_policies like '%AC\_P%' escape '\'
 order by event_timestamp_utc;
connect &sys_conn@&svc
noaudit policy ac_pp_logon by c##ac_cperson;

prompt --- AC9c: both policies in CDB$ROOT, no CONTAINER clause
-- AC_PC_POL stays enabled, so the ALTER USER matches two policies.
connect &sysdba@&cdb as sysdba
audit policy ac_pr_pol;
audit policy ac_pr_logon by c##ac_cperson whenever successful;
select to_char(sys_extract_utc(systimestamp),'YYYY-MM-DD HH24:MI:SS.FF6') t0 from dual;
connect c##ac_csvc/"AcCsvcPw_2209"@&cdb
alter user c##ac_cperson identified by "AcCpersonPw_5175" container = all;
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&cdb
connect c##ac_cdba[c##ac_cperson]/"AcCdbaPw_8841"@&svc
connect &sysdba@&cdb as sysdba
select con_id, dbusername, dbproxy_username, action_name, return_code, unified_audit_policies
  from cdb_unified_audit_trail
 where event_timestamp_utc > to_timestamp('&t0','YYYY-MM-DD HH24:MI:SS.FF6')
   and unified_audit_policies like '%AC\_P%' escape '\'
 order by event_timestamp_utc;
noaudit policy ac_pc_pol;
noaudit policy ac_pr_pol;
noaudit policy ac_pr_logon by c##ac_cperson;

prompt === AC10: may a common policy and a policy in the PDB share a name?
-- AC10a creates the PDB's first, AC10b the root's first. Each CREATE is the
-- question, so a failure is a result and does not stop the run.
whenever sqlerror continue none
prompt --- AC10a: the PDB's first
connect &sys_conn@&svc
create audit policy ac_n1 actions alter user;
connect &sysdba@&cdb as sysdba
create audit policy ac_n1 actions alter user container = all;
prompt --- AC10b: the root's first
create audit policy ac_n2 actions alter user container = all;
connect &sys_conn@&svc
create audit policy ac_n2 actions alter user;
whenever sqlerror exit failure
select distinct policy_name, common from audit_unified_policies
 where policy_name in ('AC_N1', 'AC_N2') order by policy_name, common;

prompt === teardown
connect &sysdba@&cdb as sysdba
-- The same block as the setup's, for the root's policies.
begin
  for p in (select policy_name, enabled_option, entity_name
              from audit_unified_enabled_policies
             where policy_name like 'AC\_%' escape '\'
                or policy_name like 'C##AC\_%' escape '\') loop
    begin
      execute immediate 'noaudit policy ' || p.policy_name ||
        case
          when p.enabled_option = 'BY USER' and p.entity_name <> 'ALL USERS'
            then ' by ' || p.entity_name
        end;
    exception when others then null;
    end;
  end loop;
  for p in (select distinct policy_name from audit_unified_policies
             where policy_name like 'AC\_%' escape '\'
                or policy_name like 'C##AC\_%' escape '\') loop
    begin
      execute immediate 'drop audit policy ' || p.policy_name;
    exception when others then null;
    end;
  end loop;
end;
/
connect &sys_conn@&svc
-- The same block as the setup's. There are four copies; the setup's root loop
-- says why, and they change together.
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
drop user c##ac_cperson cascade;
drop user c##ac_cdba cascade;
connect &sys_conn@&svc
select count(*) as leftover_users from dba_users
 where username like 'AC\_%' escape '\' or username like 'C##AC\_%' escape '\';
select count(*) as leftover_policies from audit_unified_policies
 where policy_name like 'AC\_%' escape '\';
-- The root's own policies: the PDB does not see one created there without
-- CONTAINER = ALL (AC8).
connect &sysdba@&cdb as sysdba
select count(*) as leftover_root_policies from audit_unified_policies
 where policy_name like 'AC\_%' escape '\' or policy_name like 'C##AC\_%' escape '\';
exit
