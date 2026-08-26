--------------------------------------------------------------------------------
-- sopuli-dba : create and grant the service account
--
-- STATUS: confirmed on 26ai Free 23.26.2.0.0 (2026-08-26). All three modes ran
--         (COMMON in CDB$ROOT, PDB and NONCDB in a PDB), both the create and
--         the already-exists paths, and both settings of grant_user_dollar and
--         grant_set_container. The mode guards were checked too: PDB in
--         CDB$ROOT gives ORA-20011 and an unknown mode ORA-20012, each exiting
--         non-zero. Untried on 19c, 21c and 11.2.
--         Review before running; try a throwaway DB first.
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

DEFINE mode          = COMMON
DEFINE svc_name      = SOPULI_SVC
DEFINE svc_tablespace = USERS

-- Set to Y to enable `sopuli creds check --method hash` and the failed-login
-- (LCOUNT) guard. This grants SELECT on SYS.USER$, exposing password verifiers.
-- See docs/design/02-oracle-privileges.md §2. Recommended for scheduled checks,
-- because the alternative — repeated login attempts — can lock the very
-- production accounts the check is monitoring.
DEFINE grant_user_dollar = N

-- Set to Y only if the tool switches containers on an open session rather than
-- connecting to each PDB service directly.
DEFINE grant_set_container = N

--------------------------------------------------------------------------------
-- Resolve the effective account name and container clause
--------------------------------------------------------------------------------
COLUMN eff_user  NEW_VALUE eff_user
COLUMN cont_all  NEW_VALUE cont_all
COLUMN cont_note NEW_VALUE cont_note

SELECT CASE WHEN UPPER('&mode') = 'COMMON' THEN 'C##&svc_name'
            ELSE '&svc_name' END                        AS eff_user,
       CASE WHEN UPPER('&mode') = 'COMMON' THEN ' CONTAINER=ALL'
            ELSE '' END                                 AS cont_all,
       SYS_CONTEXT('USERENV','CON_NAME')                AS cont_note
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
  l_con VARCHAR2(128) := SYS_CONTEXT('USERENV','CON_NAME');
BEGIN
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
--------------------------------------------------------------------------------
PROMPT
PROMPT [1] account &eff_user
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = UPPER('&eff_user');
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE USER &eff_user IDENTIFIED BY "'
                   || DBMS_RANDOM.STRING('X', 28) || 'aA1" '
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
  IF UPPER('&grant_set_container') = 'Y' AND UPPER('&mode') = 'COMMON' THEN
    EXECUTE IMMEDIATE 'GRANT SET CONTAINER TO &eff_user CONTAINER=ALL';
    DBMS_OUTPUT.PUT_LINE('granted SET CONTAINER');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 6. Report: exactly what this account now holds
--------------------------------------------------------------------------------
SET LINESIZE 200
COLUMN privilege FORMAT A32
COLUMN owner     FORMAT A10
COLUMN table_name FORMAT A20

PROMPT
PROMPT [6] report: exactly what this account now holds
PROMPT
PROMPT --- system privileges
SELECT privilege, common FROM dba_sys_privs WHERE grantee = UPPER('&eff_user');

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
