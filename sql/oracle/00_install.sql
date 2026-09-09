--------------------------------------------------------------------------------
-- sopuli-dba : create and grant the service account
--
-- STATUS: confirmed on 26ai Free 23.26.2.0.0 (2026-08-26). All three modes ran
--         (COMMON in CDB$ROOT, PDB and NONCDB in a PDB), both the create and
--         the already-exists paths, and both settings of grant_user_dollar and
--         grant_set_container. The mode guards were checked too: PDB in
--         CDB$ROOT gives ORA-20011 and an unknown mode ORA-20012, each exiting
--         non-zero. Parameters were driven both ways: defaults with no
--         arguments, and every position passed.
--         Confirmed on 21c XE 21.3.0.0.0 (2026-09-08, #380), in XEPDB1 and
--         CDB$ROOT, through the whole of tests/driver/test_oracle_install_script.py
--         and by hand as SYSDBA. It did NOT run there until this date: the
--         service account's random password was 31 bytes, which is ORA-00972
--         on every line before 23ai, so section 1 failed having created
--         nothing. Now 30.
--         Confirmed on 18c XE 18.4.0.0.0 (2026-09-08, #381), XEPDB1 and
--         CDB$ROOT, same route.
--         Confirmed on 11g XE 11.2.0.2.0 (2026-09-08, #382) in NONCDB mode,
--         which had never run anywhere. Two things stopped it there and both
--         are fixed here: SYS_CONTEXT('USERENV','CON_NAME') RAISES on a
--         non-CDB (ORA-02003) rather than answering NULL, and section 7's
--         report selected DBA_SYS_PRIVS.COMMON, a 12.1 column, which failed
--         the whole install AFTER every grant had been made. Untried on 19c.
--         Review before running; try a throwaway DB first.
--
--         grant_pwfile (position 6) added and run on the same release
--         2026-09-05 (#296): PDB mode with Y and with N, COMMON with all six
--         positions passed, and the no-argument default path -- which is the
--         one the sixth COLUMN/NEW_VALUE line exists for. The report section
--         lists SYS.V_$PWFILE_USERS under Y and not under N.
--
-- Run as SYS AS SYSDBA or an equivalent DBA.
--
-- Pick a mode:
--   NONCDB  — non-CDB database, or a single PDB with local users.
--             Run while connected to that database / PDB.
--   COMMON  — CDB, one common service user covering every container.
--             Run in CDB$ROOT. Account name gets the C## prefix.
--   PDB     — CDB, a separate local service user inside one PDB.
--             Run with the session in that PDB. Repeat per PDB.
--
-- COMMON is the usual choice when one DBA team owns the whole CDB.
-- PDB is for CDBs whose PDBs have different owners; it limits a stolen
-- credential to one container at the cost of provisioning each one.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON SIZE UNLIMITED
SET DEFINE ON
SET VERIFY OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE

--------------------------------------------------------------------------------
-- Parameters
--
-- Either edit the defaults below and run the file, or pass them positionally and
-- leave the file alone:
--
--   @00_install.sql
--   @00_install.sql PDB
--   @00_install.sql COMMON SOPULI_SVC USERS Y N N
--
--   1 mode                COMMON | PDB | NONCDB
--   2 svc_name            account name; COMMON mode prefixes it with C##
--   3 svc_tablespace      default tablespace for the account
--   4 grant_user_dollar   Y grants SELECT on SYS.USER$ -- see below
--   5 grant_set_container Y grants SET CONTAINER -- see below
--   6 grant_pwfile        Y grants SELECT on SYS.V_$PWFILE_USERS -- see below
--
-- An argument wins; anything not passed falls back to the default beside it.
--
-- **The zero-row SELECT below is load-bearing, not decoration.** SQL*Plus PROMPTS
-- for an `&1` that was never supplied, and a prompt in a piped or redirected run
-- reads the NEXT LINE OF THE SCRIPT as its answer -- so the parameter silently
-- takes a value like `EXIT` and the swallowed line never executes. Measured, not
-- feared. `COLUMN n NEW_VALUE n` against a query returning no rows defines the
-- missing positions as empty without asking, and leaves any that were supplied
-- alone; only then is it safe to read them.
--------------------------------------------------------------------------------
SET TERMOUT OFF
COLUMN 1 NEW_VALUE 1
COLUMN 2 NEW_VALUE 2
COLUMN 3 NEW_VALUE 3
COLUMN 4 NEW_VALUE 4
COLUMN 5 NEW_VALUE 5
COLUMN 6 NEW_VALUE 6
SELECT NULL AS "1", NULL AS "2", NULL AS "3", NULL AS "4", NULL AS "5", NULL AS "6"
  FROM dual WHERE 1 = 0;

-- Defaults live here, in the NVL. `grant_user_dollar=Y` enables
-- `sopuli creds check --method hash` and the failed-login (LCOUNT) guard, at the
-- cost of SELECT on SYS.USER$, which exposes password verifiers -- see
-- docs/design/02-oracle-privileges.md §2. It is recommended for scheduled checks,
-- because the alternative (repeated login attempts) can lock the very production
-- accounts the check is monitoring. `grant_set_container=Y` is for a site whose
-- tool switches containers on an open session rather than connecting to each PDB
-- service directly. `grant_pwfile=Y` enables the one account guardrail that
-- cannot run without it (§4 check 3, the password file) and costs nothing but the
-- list of accounts holding SYSDBA -- without it every run warns SOPULI-W018 that
-- the check did not run.
COLUMN p_mode NEW_VALUE mode                NOPRINT
COLUMN p_name NEW_VALUE svc_name            NOPRINT
COLUMN p_tbs  NEW_VALUE svc_tablespace      NOPRINT
COLUMN p_usr  NEW_VALUE grant_user_dollar   NOPRINT
COLUMN p_ctr  NEW_VALUE grant_set_container NOPRINT
COLUMN p_pwf  NEW_VALUE grant_pwfile        NOPRINT
SELECT NVL('&1', 'COMMON')     AS p_mode,
       NVL('&2', 'SOPULI_SVC') AS p_name,
       NVL('&3', 'USERS')      AS p_tbs,
       NVL('&4', 'N')          AS p_usr,
       NVL('&5', 'N')          AS p_ctr,
       NVL('&6', 'N')          AS p_pwf
  FROM dual;
SET TERMOUT ON

--------------------------------------------------------------------------------
-- Resolve the effective account name and container clause
--------------------------------------------------------------------------------
COLUMN eff_user  NEW_VALUE eff_user
COLUMN cont_all  NEW_VALUE cont_all
COLUMN cont_note NEW_VALUE cont_note

-- **`CON_NAME` raises on a non-CDB rather than answering NULL.** `ORA-02003:
-- invalid USERENV parameter`, measured on 11g XE 11.2.0.2.0 (#382) -- so an
-- `NVL` around it does nothing and a bare SELECT takes the whole script down
-- before it prints its banner. It is read in PL/SQL with a handler instead, and
-- the sanity block below does the same for the same reason.
--
-- `NON-CDB` rather than NULL, because the value is compared: the block below
-- refuses `mode=COMMON` unless the session is in `CDB$ROOT`, and a NULL would
-- make that comparison unknown and the refusal silently not happen. A non-CDB
-- has no common users, so being refused there is correct and the message says
-- what it found.
SET TERMOUT OFF
VARIABLE con_name VARCHAR2(128)
BEGIN
  BEGIN
    SELECT SYS_CONTEXT('USERENV','CON_NAME') INTO :con_name FROM dual;
  EXCEPTION
    WHEN OTHERS THEN
      -- ORA-02003 only. It is the one code here that carries information --
      -- 11.2 saying it has never heard of containers -- and the driver makes the
      -- same narrowing for the same query (capabilities.NO_CONTAINERS). Anything
      -- else is a real fault, and swallowing it would install under a container
      -- name this script invented.
      IF SQLCODE != -2003 THEN
        RAISE;
      END IF;
      :con_name := 'NON-CDB';
  END;
END;
/
SET TERMOUT ON

SELECT CASE WHEN UPPER('&mode') = 'COMMON' THEN 'C##&svc_name'
            ELSE '&svc_name' END                        AS eff_user,
       CASE WHEN UPPER('&mode') = 'COMMON' THEN ' CONTAINER=ALL'
            ELSE '' END                                 AS cont_all,
       :con_name                                        AS cont_note
  FROM dual;

PROMPT ============================================================
PROMPT sopuli-dba service account install
PROMPT   mode      : &mode
PROMPT   account   : &eff_user
PROMPT   container : &cont_note
PROMPT ============================================================

--------------------------------------------------------------------------------
-- Sanity: COMMON must run in CDB$ROOT; PDB/NONCDB must not
--------------------------------------------------------------------------------
PROMPT
PROMPT [check] session container is valid for mode=&mode
DECLARE
  l_con VARCHAR2(128);
BEGIN
  -- Assigned in the body and not in the DECLARE: an exception raised while
  -- initialising a declaration propagates *out* of the block, so a handler down
  -- here would never see it. That is what `ORA-02003` did on 11.2 (#382).
  BEGIN
    l_con := SYS_CONTEXT('USERENV','CON_NAME');
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE != -2003 THEN
        RAISE;   -- see the same narrowing above
      END IF;
      l_con := 'NON-CDB';
  END;
  IF UPPER('&mode') = 'COMMON' AND l_con != 'CDB$ROOT' THEN
    RAISE_APPLICATION_ERROR(-20010,
      'mode=COMMON must be run in CDB$ROOT; this session is in ' || l_con);
  END IF;
  IF UPPER('&mode') = 'PDB' AND l_con = 'CDB$ROOT' THEN
    RAISE_APPLICATION_ERROR(-20011,
      'mode=PDB must be run inside the target PDB, not CDB$ROOT');
  END IF;
  IF UPPER('&mode') NOT IN ('COMMON','PDB','NONCDB') THEN
    RAISE_APPLICATION_ERROR(-20012, 'mode must be COMMON, PDB or NONCDB');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 1. The account
--
-- Created with a random password and PASSWORD EXPIRE: it is unusable until a
-- DBA sets a real one. Store that password in the vault, or use an Oracle
-- Wallet / external authentication and never give it a usable password at all.
--
-- **27 + 3 = 30 bytes, and the 30 is a ceiling rather than a preference.**
-- Oracle raised the password limit past 30 bytes at 23ai; every earlier line
-- still refuses a 31st with `ORA-00972: identifier is too long`, and refuses it
-- from inside this block, so the script fails at step 1 having created nothing.
-- Measured 2026-09-08 (#380): 31 bytes is accepted on 26ai 23.26.2.0.0 and
-- rejected on 21c XE 21.3, 18c XE 18.4 and 11g XE 11.2. The script ran only on
-- 26ai until now, which is why a 31-byte password looked fine.
-- `aA1` is appended rather than left to chance because `STRING('X', n)` draws
-- from uppercase and digits only, and a verify function wants a lowercase too.
--------------------------------------------------------------------------------
PROMPT
PROMPT [1] account &eff_user
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = UPPER('&eff_user');
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE USER &eff_user IDENTIFIED BY "'
                   || DBMS_RANDOM.STRING('X', 27) || 'aA1" '
                   || 'DEFAULT TABLESPACE &svc_tablespace '
                   || 'PASSWORD EXPIRE' || '&cont_all';
    DBMS_OUTPUT.PUT_LINE('created &eff_user (random password, expired - set it now)');
  ELSE
    DBMS_OUTPUT.PUT_LINE('&eff_user already exists; its password is left alone');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 2. Core grants
--
-- ALTER USER is a system privilege with no object scope: this account can
-- change ANY user's password in its container(s), including SYS. That is
-- accepted deliberately — see docs/design/02-oracle-privileges.md §1. Treat the
-- credential accordingly, and enable auditing (01_audit_policy.sql).
--------------------------------------------------------------------------------
PROMPT
PROMPT [2] core grants
PROMPT   CREATE SESSION
GRANT CREATE SESSION TO &eff_user&cont_all;
PROMPT   ALTER USER
GRANT ALTER USER     TO &eff_user&cont_all;

--------------------------------------------------------------------------------
-- 3. Dictionary reads
--
-- Explicit views rather than SELECT_CATALOG_ROLE, so a privilege review is a
-- one-screen job. Swapping in the role is fine if your site prefers it; it does
-- NOT include SYS.USER$.
--
-- DBA_ROLE_PRIVS is what the client-side guardrail reads to refuse an account
-- holding DBA, PDB_DBA, CDB_DBA or AUDIT_ADMIN (§4 check 4). Without it the tool
-- refuses to describe an account at all, rather than reading "cannot see any
-- roles" as "holds no admin role" — which would turn a safety check into a
-- silent pass.
--------------------------------------------------------------------------------
PROMPT
PROMPT [3] dictionary reads
PROMPT   SELECT ON DBA_USERS
GRANT SELECT ON SYS.DBA_USERS      TO &eff_user&cont_all;
PROMPT   SELECT ON DBA_PROFILES
GRANT SELECT ON SYS.DBA_PROFILES   TO &eff_user&cont_all;
PROMPT   SELECT ON DBA_ROLE_PRIVS
GRANT SELECT ON SYS.DBA_ROLE_PRIVS TO &eff_user&cont_all;
PROMPT   SELECT ON V$DATABASE
GRANT SELECT ON SYS.V_$DATABASE    TO &eff_user&cont_all;
PROMPT   SELECT ON V$INSTANCE
GRANT SELECT ON SYS.V_$INSTANCE    TO &eff_user&cont_all;

-- V$PDBS is meaningful in the root only
PROMPT   SELECT ON V$PDBS (COMMON only)
BEGIN
  IF UPPER('&mode') = 'COMMON' THEN
    EXECUTE IMMEDIATE 'GRANT SELECT ON SYS.V_$PDBS TO &eff_user';
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 4. Optional: SYS.USER$ for hash-mode verification and the LCOUNT guard
--------------------------------------------------------------------------------
PROMPT
PROMPT [4] optional: SYS.USER$ (grant_user_dollar=&grant_user_dollar)
BEGIN
  IF UPPER('&grant_user_dollar') = 'Y' THEN
    EXECUTE IMMEDIATE 'GRANT SELECT ON SYS.USER$ TO &eff_user&cont_all';
    DBMS_OUTPUT.PUT_LINE('granted SELECT ON SYS.USER$ '
      || '(enables check --method hash and the failed-login guard)');
  ELSE
    DBMS_OUTPUT.PUT_LINE('SYS.USER$ not granted: check --method hash unavailable, '
      || 'and login-based checks run without the LCOUNT lockout guard');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 5. Optional: SET CONTAINER
--------------------------------------------------------------------------------
PROMPT
PROMPT [5] optional: SET CONTAINER (grant_set_container=&grant_set_container)
BEGIN
  IF UPPER('&grant_set_container') != 'Y' THEN
    NULL;
  ELSIF UPPER('&mode') = 'COMMON' THEN
    EXECUTE IMMEDIATE 'GRANT SET CONTAINER TO &eff_user CONTAINER=ALL';
    DBMS_OUTPUT.PUT_LINE('granted SET CONTAINER');
  ELSE
    -- Asked for and not applicable, which is not the same as not asked for.
    -- SET CONTAINER moves a session between containers, so it means nothing in
    -- PDB or NONCDB mode and nothing at all on a release with no containers.
    -- Said out loud because the alternative is a parameter that was honoured and
    -- one that was ignored looking identical -- the failure mode #231 found
    -- twice in this file (#382).
    DBMS_OUTPUT.PUT_LINE('SET CONTAINER not granted: mode=&mode installs a local '
                      || 'account in one container, so there is nowhere to switch to. '
                      || 'The grant is COMMON-mode only.');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 6. Optional: V$PWFILE_USERS for guardrail 3
--
-- The client-side guardrails refuse an account that appears in the password file
-- (docs/design/02-oracle-privileges.md §4 check 3). Without this grant the view
-- answers ORA-00942 and the check has no input: the tool says so on every run
-- (SOPULI-W018) rather than treating "could not look" as "not a member", and
-- applies anyway. With it, the check runs.
--
-- It also lets `doctor --check-privileges` audit §3's SYSDBA and SYSOPER rows for
-- THIS account, which it otherwise reports as unchecked (§3). Same view, and the
-- audit asks about the service account itself rather than about a target one.
--
-- Worth taking on an estate that has any site-created account holding SYSDBA: it
-- reads ORACLE_MAINTAINED = 'N' and may hold no roles at all, so checks 2, 4 and
-- 5 all pass it and this is the only one that does not.
--------------------------------------------------------------------------------
PROMPT
PROMPT [6] optional: V$PWFILE_USERS (grant_pwfile=&grant_pwfile)
BEGIN
  IF UPPER('&grant_pwfile') = 'Y' THEN
    EXECUTE IMMEDIATE 'GRANT SELECT ON SYS.V_$PWFILE_USERS TO &eff_user&cont_all';
    DBMS_OUTPUT.PUT_LINE('granted SELECT ON SYS.V_$PWFILE_USERS '
      || '(enables guardrail 3, and the SYSDBA/SYSOPER rows of the audit)');
  ELSE
    DBMS_OUTPUT.PUT_LINE('V$PWFILE_USERS not granted: guardrail 3 cannot run, '
      || 'every run warns SOPULI-W018 that it did not, and the privilege '
      || 'audit reports SYSDBA/SYSOPER as unchecked');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 7. Report: exactly what this account now holds
--------------------------------------------------------------------------------
SET LINESIZE 200
COLUMN privilege FORMAT A32
COLUMN owner     FORMAT A10
COLUMN table_name FORMAT A20

PROMPT
PROMPT [7] report: exactly what this account now holds
PROMPT
-- `DBA_SYS_PRIVS.COMMON` arrived with multitenant in 12.1. On 11.2 naming it is
-- `ORA-00904`, and under this file's `WHENEVER SQLERROR EXIT SQL.SQLCODE` that
-- takes the whole install down **after every grant has already been made** --
-- measured on 11g XE 11.2.0.2.0 (#382): the account existed, held exactly the
-- right grants, and the script exited 136. A report is diagnostic and must never
-- be the reason an install fails.
--
-- Resolved rather than branched on a version (invariant 3 in the small): ask the
-- dictionary whether the column is there, and select a literal in its place
-- where it is not. `COUNT(*)` and not `EXISTS`, which 11.2 does not allow in a
-- SELECT list.
SET TERMOUT OFF
COLUMN p_common NEW_VALUE common_col NOPRINT
SELECT CASE WHEN (SELECT COUNT(*) FROM dba_tab_columns
                   WHERE table_name = 'DBA_SYS_PRIVS' AND column_name = 'COMMON') > 0
            THEN 'common'
            ELSE '''n/a'' AS common' END AS p_common
  FROM dual;
SET TERMOUT ON

PROMPT --- system privileges
SELECT privilege, &common_col FROM dba_sys_privs WHERE grantee = UPPER('&eff_user');

PROMPT --- roles (expect none)
SELECT granted_role FROM dba_role_privs WHERE grantee = UPPER('&eff_user');

PROMPT --- object privileges
SELECT owner, table_name, privilege FROM dba_tab_privs
 WHERE grantee = UPPER('&eff_user') ORDER BY table_name;

PROMPT --- things that should NOT appear above
SELECT privilege AS over_granted FROM dba_sys_privs
 WHERE grantee = UPPER('&eff_user')
   AND privilege IN ('SELECT ANY DICTIONARY','ALTER PROFILE','CREATE USER',
                     'DROP USER','BECOME USER','ALTER SYSTEM',
                     'GRANT ANY PRIVILEGE','GRANT ANY ROLE')
UNION ALL
SELECT 'ROLE: ' || granted_role FROM dba_role_privs
 WHERE grantee = UPPER('&eff_user')
   AND granted_role IN ('DBA','PDB_DBA','CDB_DBA','SELECT_ANY_DICTIONARY');

PROMPT
PROMPT Next steps:
PROMPT   1. set a real password for &eff_user, or configure wallet auth,
PROMPT      and store it where the tool's config points
PROMPT   2. enable auditing:  @01_audit_policy.sql
PROMPT   3. check from the tool:  sopuli doctor --check-privileges --target <name>
PROMPT
