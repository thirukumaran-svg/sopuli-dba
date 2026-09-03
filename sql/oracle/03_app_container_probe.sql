--------------------------------------------------------------------------------
-- sopuli-dba : application container probe   (v1)
--
-- Answers #204, which docs/design/02-oracle-privileges.md §2 and
-- src/sopuli/driver/oracle/capabilities.py both refuse to answer from reasoning:
--
--   1. can a session tell an application root and an application PDB from an
--      ordinary PDB, using only what §2 grants?
--   2. what do the CDB common-user rules actually mean inside one?
--
-- `resolve_scope` answers three of P1's five scopes from
-- SYS_CONTEXT('USERENV','CON_NAME'), which needs no grant. It cannot answer
-- `app_root` or `app_pdb`, so both read as `pdb` -- and container_clause()'s
-- refusal of an application container, written against exactly those two values,
-- has therefore never been able to fire. This script measures what a real one
-- does, so the refusal can be written against something observed.
--
-- THROWAWAY DATABASES ONLY. Creates an application container, an application
-- PDB, tablespaces and several accounts, sets db_create_file_dest at the
-- instance level, and leaves all of it behind. §7 drops what it made.
--
--
-- RESULTS SO FAR
--   26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), 2026-09-03, CDB$ROOT,
--   as SYS. Every line below is from a run of this script.
--
--   DETECTION -- and this is the finding that removes the grant trade #204 asked
--   to argue. There is no trade: the two attributes need no grant at all.
--
--     container    IS_APPLICATION_ROOT  IS_APPLICATION_PDB
--     CDB$ROOT     NO                   NO
--     FREEPDB1     NO                   NO
--     ACME_ROOT    YES                  NO
--     ACME_ALPHA   NO                   YES
--
--   (con_id is printed too, but it is whatever the instance allocates and is not
--   part of the result.)
--
--   Read identically by a service account holding exactly §2's PDB-mode grant
--   set, which in the same session could not read any of the three views that
--   carry the same fact:
--
--     V$PDBS    -> ORA-00942
--     DBA_PDBS  -> ORA-00942
--     CDB_PDBS  -> ORA-00942
--
--   So detection is available on the same terms as CON_NAME, which is why the
--   scope is resolved from USERENV in the first place: a half-installed service
--   account must still be able to say what it is connected to.
--
--   THE FALLBACK IS A RAISE, NOT A NULL. An unknown USERENV attribute gives
--   ORA-02003, the code capabilities.py already knows as NO_CONTAINERS -- so on a
--   release predating 12.2 these two probes fail the way CON_NAME does on 11.2.
--   Same code, different fact ("no application containers on this release" rather
--   than "no containers at all"), same conclusion.
--
--   SEMANTICS, in an application ROOT:
--     - CREATE USER ... CONTAINER=CURRENT  -> ORA-65049. A local account cannot
--       exist here at all.
--     - CREATE USER with NO container clause -> common=YES. The default is
--       application-common, not local.
--     - a C## name, either way -> ORA-60534. Common names are forbidden here,
--       so container_clause()'s is_common test can never be true in one.
--     - ALTER USER ... IDENTIFIED BY with NO container clause -> accepted, and
--       the new password authenticates in the application root AND in an
--       already-synced application PDB, with no sync in between. Measured by
--       login in §5, where the new password gives ORA-01045 in the application
--       PDB (authentication passed, CREATE SESSION missing) and the old one
--       gives ORA-01017 (authentication failed). password_change_date reads
--       EMPTY there throughout and would have reported the opposite.
--
--   SEMANTICS, in an application PDB:
--     - a local account is entirely ordinary: CONTAINER=CURRENT creates it,
--       common=NO, and a plain ALTER USER ... IDENTIFIED BY rotates it.
--     - an application-common account is refused by Oracle either way:
--       ORA-65066 with no clause, ORA-65040 with CONTAINER=ALL.
--     - a C## name -> ORA-60534, as in the root.
--
--   WHAT THAT MEANS FOR THE REFUSAL, which is the reason to run this at all.
--   The hazard is real, it is confined to the application ROOT, and it is the
--   opposite shape to the one 02-oracle-privileges.md guessed at. The doc worried
--   that CONTAINER=ALL means something narrower there. It does -- but the tool
--   never gets that far: it sees a name without a C## prefix, concludes "local
--   account", appends no clause, and issues a statement that Oracle accepts and
--   applies across the whole application container. The danger is not the clause
--   meaning less than it looks. It is that the ABSENCE of a clause already means
--   more.
--
--   The application PDB half needs no refusal. The safe case is ordinary and the
--   dangerous case is refused by Oracle before the tool can get it wrong.
--
--
-- HOW TO RUN
--   Set the DEFINEs in §0 and run as SYSDBA against CDB$ROOT:
--
--     sqlplus -s "/ as sysdba" @03_app_container_probe.sql
--
--   The script connects out to the probe account twice in §5 and back as SYSDBA
--   afterwards, so &hostport must reach this same instance. Note that CONNECT puts
--   the password on the SQL*Plus command line and therefore into `ps`; that is
--   acceptable for a throwaway probe and is why the passwords here are visibly
--   disposable placeholders rather than anything resembling a real one.
--
--   Needs Oracle Managed Files: CREATE PLUGGABLE DATABASE is ORA-65016 without
--   either that or FILE_NAME_CONVERT. Where db_create_file_dest is already set
--   the script keeps the site's own value and &omf_dest is never used; where it
--   is empty, &omf_dest is set SCOPE=MEMORY. Either way §7 puts back exactly what
--   §0 read, so a run leaves the parameter as it found it.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON SIZE UNLIMITED
SET DEFINE ON
SET VERIFY OFF
SET LINESIZE 200
SET PAGESIZE 100
SET FEEDBACK OFF

--------------------------------------------------------------------------------
-- 0. Parameters
--------------------------------------------------------------------------------
DEFINE hostport     = "localhost:1521"
DEFINE app_root     = "ACME_ROOT"
DEFINE app_pdb      = "ACME_ALPHA"
DEFINE ordinary_pdb = "FREEPDB1"
DEFINE tbs          = "USERS"
DEFINE omf_dest     = "/opt/oracle/oradata/FREE"

-- Disposable. Rotated within the run, dropped in §7, and the account they
-- belong to holds CREATE SESSION and nothing else.
DEFINE pwd_first  = "Probe-Only-1"
DEFINE pwd_second = "Probe-Only-2"

COLUMN x FORMAT A96
COLUMN saved_omf NEW_VALUE saved_omf NOPRINT
SELECT value AS saved_omf FROM v$parameter WHERE name = 'db_create_file_dest';

PROMPT
PROMPT ================================================================
PROMPT sopuli-dba application container probe
PROMPT ================================================================

--------------------------------------------------------------------------------
-- 1. Build an application container and an application PDB
--------------------------------------------------------------------------------
PROMPT
PROMPT [1] build

WHENEVER SQLERROR EXIT SQL.SQLCODE

-- &omf_dest is a FALLBACK, not an override: NVL keeps whatever the instance
-- already has, so this is a no-op on a site that has configured OMF and only
-- supplies a destination where there was none. §7 restores &saved_omf regardless.
COLUMN omf_to_use NEW_VALUE omf_to_use NOPRINT
SELECT NVL(value, '&omf_dest') AS omf_to_use
  FROM v$parameter WHERE name = 'db_create_file_dest';
ALTER SYSTEM SET db_create_file_dest = '&omf_to_use' SCOPE=MEMORY;

CREATE PLUGGABLE DATABASE &app_root AS APPLICATION CONTAINER
  ADMIN USER acme_adm IDENTIFIED BY "&pwd_first";
ALTER PLUGGABLE DATABASE &app_root OPEN;

ALTER SESSION SET CONTAINER = &app_root;
CREATE TABLESPACE &tbs DATAFILE SIZE 50M AUTOEXTEND ON;
CREATE PLUGGABLE DATABASE &app_pdb
  ADMIN USER acme_adm IDENTIFIED BY "&pwd_first";
ALTER PLUGGABLE DATABASE &app_pdb OPEN;

ALTER SESSION SET CONTAINER = &app_pdb;
CREATE TABLESPACE &tbs DATAFILE SIZE 50M AUTOEXTEND ON;

ALTER SESSION SET CONTAINER = CDB$ROOT;
PROMPT   built &app_root (application container) and &app_pdb (application PDB)

--------------------------------------------------------------------------------
-- 2. Detection: what a session can see about itself, with no grant
--
-- The whole question of #204 is in this section. CON_NAME already resolves three
-- of P1's five scopes; these two attributes are what resolve the other two, and
-- the point is that they are USERENV, so nothing has to be granted to read them.
--------------------------------------------------------------------------------
PROMPT
PROMPT [2] detection -- SYS_CONTEXT('USERENV', ...) in four containers

ALTER SESSION SET CONTAINER = CDB$ROOT;
SELECT RPAD(SYS_CONTEXT('USERENV','CON_NAME'), 12)
    || ' con_id=' || RPAD(SYS_CONTEXT('USERENV','CON_ID'), 3)
    || ' IS_APPLICATION_ROOT=' || RPAD(SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT'), 4)
    || ' IS_APPLICATION_PDB=' || SYS_CONTEXT('USERENV','IS_APPLICATION_PDB') AS x
  FROM dual;
ALTER SESSION SET CONTAINER = &ordinary_pdb;
SELECT RPAD(SYS_CONTEXT('USERENV','CON_NAME'), 12)
    || ' con_id=' || RPAD(SYS_CONTEXT('USERENV','CON_ID'), 3)
    || ' IS_APPLICATION_ROOT=' || RPAD(SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT'), 4)
    || ' IS_APPLICATION_PDB=' || SYS_CONTEXT('USERENV','IS_APPLICATION_PDB') AS x
  FROM dual;
ALTER SESSION SET CONTAINER = &app_root;
SELECT RPAD(SYS_CONTEXT('USERENV','CON_NAME'), 12)
    || ' con_id=' || RPAD(SYS_CONTEXT('USERENV','CON_ID'), 3)
    || ' IS_APPLICATION_ROOT=' || RPAD(SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT'), 4)
    || ' IS_APPLICATION_PDB=' || SYS_CONTEXT('USERENV','IS_APPLICATION_PDB') AS x
  FROM dual;
ALTER SESSION SET CONTAINER = &app_pdb;
SELECT RPAD(SYS_CONTEXT('USERENV','CON_NAME'), 12)
    || ' con_id=' || RPAD(SYS_CONTEXT('USERENV','CON_ID'), 3)
    || ' IS_APPLICATION_ROOT=' || RPAD(SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT'), 4)
    || ' IS_APPLICATION_PDB=' || SYS_CONTEXT('USERENV','IS_APPLICATION_PDB') AS x
  FROM dual;

PROMPT
PROMPT   an unknown attribute raises rather than returning NULL:

WHENEVER SQLERROR CONTINUE
SELECT SYS_CONTEXT('USERENV','no_such_attribute_at_all') AS x FROM dual;

--------------------------------------------------------------------------------
-- 3. The same two questions under §2's grant set
--
-- A service account installed by 00_install.sql in PDB mode holds SELECT on
-- DBA_USERS, DBA_PROFILES, DBA_ROLE_PRIVS, V$DATABASE and V$INSTANCE -- and
-- V$PDBS only in COMMON mode, in the root. So the three views that carry
-- APPLICATION_ROOT / APPLICATION_PDB are all out of reach here, and USERENV is
-- the only source left. That is the comparison this section makes.
--------------------------------------------------------------------------------
PROMPT
PROMPT [3] the same, as an account holding exactly §2's PDB-mode grants

ALTER SESSION SET CONTAINER = &app_pdb;
CREATE USER acme_probe_svc IDENTIFIED BY "&pwd_first"
  DEFAULT TABLESPACE &tbs CONTAINER=CURRENT;
GRANT CREATE SESSION            TO acme_probe_svc;
GRANT ALTER USER                TO acme_probe_svc;
GRANT SELECT ON SYS.DBA_USERS      TO acme_probe_svc;
GRANT SELECT ON SYS.DBA_PROFILES   TO acme_probe_svc;
GRANT SELECT ON SYS.DBA_ROLE_PRIVS TO acme_probe_svc;
GRANT SELECT ON SYS.V_$DATABASE    TO acme_probe_svc;
GRANT SELECT ON SYS.V_$INSTANCE    TO acme_probe_svc;

CONNECT acme_probe_svc/"&pwd_first"@&hostport/&app_pdb

SELECT 'as ' || USER || ' in ' || SYS_CONTEXT('USERENV','CON_NAME')
    || ': IS_APPLICATION_ROOT=' || SYS_CONTEXT('USERENV','IS_APPLICATION_ROOT')
    || ' IS_APPLICATION_PDB=' || SYS_CONTEXT('USERENV','IS_APPLICATION_PDB') AS x
  FROM dual;

PROMPT   and the three views that carry the same fact:
SELECT 'V$PDBS   -> ' || COUNT(*) AS x FROM v$pdbs;
SELECT 'DBA_PDBS -> ' || COUNT(*) AS x FROM dba_pdbs;
SELECT 'CDB_PDBS -> ' || COUNT(*) AS x FROM cdb_pdbs;

CONNECT / AS SYSDBA

--------------------------------------------------------------------------------
-- 4. Common-user semantics, measured rather than assumed
--
-- container_clause() decides between a plain ALTER USER and CONTAINER=ALL on a
-- C## prefix and the cdb_root scope. Neither test means anything here, and this
-- section is what establishes that.
--------------------------------------------------------------------------------
PROMPT
PROMPT [4] common-user semantics

PROMPT
PROMPT   4a. application ROOT: a local account (expect ORA-65049)
ALTER SESSION SET CONTAINER = &app_root;
CREATE USER acme_local_probe IDENTIFIED BY "&pwd_first"
  DEFAULT TABLESPACE &tbs CONTAINER=CURRENT;

PROMPT
PROMPT   4b. application ROOT: a C## name (expect ORA-60534)
CREATE USER c##acme_probe IDENTIFIED BY "&pwd_first" DEFAULT TABLESPACE &tbs;

PROMPT
PROMPT   4c. application ROOT: no container clause -- what does it default to?
CREATE USER acme_common_user IDENTIFIED BY "&pwd_first"
  DEFAULT TABLESPACE &tbs;
SELECT 'acme_common_user common=' || common AS x
  FROM dba_users WHERE username = 'ACME_COMMON_USER';

PROMPT
PROMPT   4d. application PDB: a local account is ordinary
ALTER SESSION SET CONTAINER = &app_pdb;
CREATE USER acme_alpha_user IDENTIFIED BY "&pwd_first"
  DEFAULT TABLESPACE &tbs CONTAINER=CURRENT;
ALTER USER acme_alpha_user IDENTIFIED BY "&pwd_second";
SELECT 'acme_alpha_user common=' || common
    || ' oracle_maintained=' || oracle_maintained
    || ' -- plain ALTER USER accepted' AS x
  FROM dba_users WHERE username = 'ACME_ALPHA_USER';

PROMPT
PROMPT   4e. application PDB: an application-common account, no clause
PROMPT       (expect ORA-65066)
ALTER PLUGGABLE DATABASE APPLICATION ALL SYNC;
ALTER USER acme_common_user IDENTIFIED BY "&pwd_second";

PROMPT
PROMPT   4f. application PDB: the same with CONTAINER=ALL (expect ORA-65040)
ALTER USER acme_common_user IDENTIFIED BY "&pwd_second" CONTAINER=ALL;

--------------------------------------------------------------------------------
-- 5. What the tool would actually issue in an application root
--
-- The account name has no C## prefix, so container_clause() returns "" and the
-- statement carries no container clause at all. This section measures what that
-- statement does.
--
-- IT IS MEASURED BY LOGIN, and the two error codes are the measurement:
--
--   ORA-01045  authentication PASSED, authorisation failed -- the password is
--              the new one. The privilege is missing because a GRANT issued in
--              an application root outside an application installation does not
--              reach an application PDB, which is a fact about the sync and not
--              about the password.
--   ORA-01017  authentication FAILED -- the password is not this one.
--
-- The contrast is what carries the result: the new password gives ORA-01045 in
-- the application PDB and the old one gives ORA-01017 there. So the rotation
-- issued in the root, with no container clause and no sync afterwards, reached
-- the application PDB.
--
-- password_change_date cannot answer this. The application PDB's copy reads
-- EMPTY after the rotation the login proves it received -- which is the same
-- reason `check` defaults to login rather than to a dictionary read (Q1, #86).
--------------------------------------------------------------------------------
PROMPT
PROMPT [5] a plain ALTER USER in an application root

ALTER SESSION SET CONTAINER = &app_root;
GRANT CREATE SESSION TO acme_common_user;
ALTER USER acme_common_user IDENTIFIED BY "&pwd_second";
PROMPT   issued: ALTER USER acme_common_user IDENTIFIED BY *** (no container clause)

PROMPT
PROMPT   NEW password, application ROOT (expect CONNECTED):
CONNECT acme_common_user/"&pwd_second"@&hostport/&app_root
SELECT 'CONNECTED as ' || USER || ' in ' || SYS_CONTEXT('USERENV','CON_NAME') AS x FROM dual;

PROMPT
PROMPT   NEW password, already-synced application PDB. Expect ORA-01045:
PROMPT   the password is right, the privilege did not sync.
CONNECT acme_common_user/"&pwd_second"@&hostport/&app_pdb

PROMPT
PROMPT   OLD password, application ROOT (expect ORA-01017):
CONNECT acme_common_user/"&pwd_first"@&hostport/&app_root

PROMPT
PROMPT   OLD password, application PDB. Expect ORA-01017, not ORA-01045:
PROMPT   this is the contrast that makes the line above mean something.
CONNECT acme_common_user/"&pwd_first"@&hostport/&app_pdb

CONNECT / AS SYSDBA
ALTER SESSION SET CONTAINER = &app_pdb;
SELECT 'application PDB password_change_date=['
    || NVL(TO_CHAR(password_change_date, 'YYYY-MM-DD HH24:MI:SS'), 'NULL')
    || '] -- empty; the login above says it changed anyway' AS x
  FROM dba_users WHERE username = 'ACME_COMMON_USER';

--------------------------------------------------------------------------------
-- 6. Findings
--------------------------------------------------------------------------------
PROMPT
PROMPT [6] findings
PROMPT   - app_root and app_pdb are detectable from USERENV, with no grant.
PROMPT   - an unknown USERENV attribute raises ORA-02003, so a release without
PROMPT     these two fails the way 11.2 fails CON_NAME.
PROMPT   - in an application root every account is application-common, C## names
PROMPT     are forbidden, and a statement with NO container clause is already
PROMPT     container-wide. That is the hazard, and it is the app_root half only.
PROMPT   - in an application PDB the safe case is ordinary and the dangerous case
PROMPT     is refused by Oracle. No refusal of our own is needed there.

--------------------------------------------------------------------------------
-- 7. Teardown
--
-- Unpluggable state only. The instance parameter is put back to the value §0
-- read, which matters because §1 set it globally rather than for this session --
-- and is a no-op in the case where §1 was one too.
--------------------------------------------------------------------------------
PROMPT
PROMPT [7] teardown

ALTER SESSION SET CONTAINER = CDB$ROOT;
ALTER PLUGGABLE DATABASE &app_pdb CLOSE IMMEDIATE;
DROP PLUGGABLE DATABASE &app_pdb INCLUDING DATAFILES;
ALTER PLUGGABLE DATABASE &app_root CLOSE IMMEDIATE;
DROP PLUGGABLE DATABASE &app_root INCLUDING DATAFILES;
ALTER SYSTEM SET db_create_file_dest = '&saved_omf' SCOPE=MEMORY;

PROMPT   dropped &app_pdb and &app_root; db_create_file_dest restored
PROMPT
EXIT
