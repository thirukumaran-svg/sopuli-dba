--------------------------------------------------------------------------------
-- sopuli-dba : auditing
--
-- STATUS: confirmed on 26ai Free 23.26.2.0.0 (2026-08-26) against a COMMON
--         install, both the create and the already-exists paths. The section 4
--         queries were checked against a real audited ALTER USER, including the
--         CLIENT_IDENTIFIER correlation in section 5. Run with the default
--         svc_user and with one passed.
--         Confirmed on 21c XE 21.3.0.0.0 (2026-09-08, #380) through
--         tests/driver/test_oracle_install_script.py, which runs it.
--         Note the container: gvenzl/oracle-xe ships AUDIT_TRAIL = NONE and
--         captures nothing on it, so a policy that was created and enabled
--         still records no rows. Setting the parameter and restarting is
--         what makes the section 4 queries mean anything -- see
--         02_password_leak_probe.sql section 1.
--         Confirmed on 18c XE 18.4.0.0.0 (2026-09-08, #381), same route and
--         the same AUDIT_TRAIL caveat.
--         Run on 11g XE 11.2.0.2.0 (2026-09-08, #382), where it now REFUSES:
--         audit policies arrived in 12.1 and section 0 stops with ORA-20020
--         naming the release and the traditional-auditing statement to use
--         instead. Before that it produced four ORA-00942s and left the
--         reader to work out why.
--         Confirmed on 19c EE 19.3.0.0.0 (2026-09-28, #479) in ORCLPDB1
--         (svc_user ACME_SVC, create then already-exists) and in CDB$ROOT
--         (C##SOPULI_SVC), with AUDIT_TRAIL = DB,EXTENDED set first -- this
--         image ships NONE, like the gvenzl ones.
--
--         The per-container policies and the personal-account list were
--         confirmed on 26ai Free 23.26.2.0.0 (2026-10-17, #812) through
--         tests/driver/test_oracle_install_script.py, in CDB$ROOT and in
--         FREEPDB1. The runs above on other releases were made before them,
--         and those releases are untried with them.
--
-- The service account holds ALTER USER, which has no object scope. Unified
-- auditing is therefore not housekeeping — it is the compensating control for
-- the privilege model. Enable it before the first rotation.
--
-- Where to run it. The script creates different policies in CDB$ROOT and in
-- other containers, because a policy covers different accounts in each
-- (13_audit_coverage_probe.sql AC8 and AC9):
--
--   CDB$ROOT         common policies, CONTAINER = ALL, named SOPULI_CDB_*.
--                    They record common accounts in every container: the
--                    service account, and common personal accounts. They
--                    record no local account
--   a PDB, non-CDB   local policies, named SOPULI_*. They record every
--                    account in that container, common accounts too
--
-- A policy created in CDB$ROOT without CONTAINER = ALL records nothing in a
-- PDB, so the script never creates one there. It drops a root policy that an
-- older copy of this script created that way.
--
--   NONCDB or PDB install   run it once, in the same container as
--                           00_install.sql
--   COMMON install          run it in CDB$ROOT. Also run it in each PDB that
--                           has local DBAs or local personal accounts,
--                           passing C##SOPULI_SVC. Without that run, a local
--                           DBA's ALTER USER in the PDB is not recorded
--
-- The names differ between the root and a PDB because a common policy and a
-- PDB's own policy may have one name (AC10). A check by name would then find
-- the common one and skip creating the PDB's own.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON
SET DEFINE ON
SET VERIFY OFF

-- Errors are fatal here, as in 00_install.sql. Without this SQL*Plus continues
-- past an ORA- or SP2- error and still exits 0, so an automated run cannot tell
-- a working install from a broken one -- and a parameter that failed to resolve
-- would leave `&svc_user` undefined, whereupon the prompt eats the script.
WHENEVER SQLERROR EXIT SQL.SQLCODE
--------------------------------------------------------------------------------
-- Parameters
--
--   @01_audit_policy.sql [svc_user] [personal_accounts]
--
--   1 svc_user           the account 00_install.sql created. Defaults to the
--                        COMMON name; pass SOPULI_SVC for a NONCDB or PDB
--                        install.
--   2 personal_accounts  optional. A comma-separated list of the personal
--                        accounts the tool resets, such as
--                        ACME_DEV_ALICE,ACME_DEV_BOB. The script then also
--                        records their successful logons (section 3). In
--                        CDB$ROOT, name common accounts. In another container,
--                        name the accounts that log on there, local or common.
--                        Every name must be an existing account. Running again
--                        with a longer list adds only the new names.
--
-- The zero-row SELECT is not decoration: SQL*Plus PROMPTS for an `&1` that was
-- never supplied, and a prompt in a piped run reads the next line of the script
-- as its answer. `COLUMN n NEW_VALUE n` defines the missing positions as empty
-- without asking. 00_install.sql's parameter block has the long version.
--------------------------------------------------------------------------------
SET TERMOUT OFF
COLUMN 1 NEW_VALUE 1
COLUMN 2 NEW_VALUE 2
SELECT NULL AS "1", NULL AS "2" FROM dual WHERE 1 = 0;
COLUMN p_user NEW_VALUE svc_user NOPRINT
COLUMN p_persons NEW_VALUE persons NOPRINT
SELECT NVL('&1', 'C##SOPULI_SVC') AS p_user, '&2' AS p_persons FROM dual;
SET TERMOUT ON

--------------------------------------------------------------------------------
-- 0. Unified auditing, or nothing this script can do
--
-- Every statement below is `CREATE AUDIT POLICY` / `AUDIT POLICY`, which arrived
-- in 12.1. On 11.2 the whole file is `ORA-00942: table or view does not exist`
-- against `AUDIT_UNIFIED_POLICIES`, four times, wrapped in `ORA-06550` -- an
-- operator is told a view is missing and left to work out which release they are
-- on and why (measured on 11g XE 11.2.0.2.0, #382; the script exited 150, so it
-- did at least fail rather than pretend).
--
-- **The refusal is the fix, not an 11.2 path.** Traditional `AUDIT ALTER USER`
-- into `DBA_AUDIT_TRAIL` is the equivalent there, and adding it would be a
-- second audit story for the tool to own -- `02-oracle-privileges.md` §5 is
-- written entirely around unified auditing, and what it should say about a
-- release without it is a design decision rather than a missing statement
-- (#382). Until that is answered, this stops early and says which release it
-- needs, so the operator can decide rather than debug.
--------------------------------------------------------------------------------
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  BEGIN
    EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM audit_unified_policies WHERE ROWNUM = 1'
      INTO l_cnt;
  EXCEPTION
    WHEN OTHERS THEN
      -- ORA-00942 only: the view is not there, which is what "no unified
      -- auditing" looks like. ORA-01031 from the same read would mean the
      -- session may not look, and rewriting that as "this release needs 12.1"
      -- would send an operator to upgrade a database that is already new enough.
      IF SQLCODE != -942 THEN
        RAISE;
      END IF;
      RAISE_APPLICATION_ERROR(-20020,
        'unified auditing is not available on this release (needs 12.1 or later): '
        || SQLERRM || '. Audit ALTER USER with traditional auditing instead -- '
        || 'AUDIT ALTER USER BY ACCESS; and set AUDIT_TRAIL = db,extended -- '
        || 'and see docs/design/02-oracle-privileges.md section 5');
  END;
END;
/

--------------------------------------------------------------------------------
-- Which container this is, and so which policies to create
--
-- CON_NAME is safe to read here: it raises ORA-02003 only on 11.2, and section
-- 0 has already stopped there. A non-CDB answers its own name.
--------------------------------------------------------------------------------
SET TERMOUT OFF
COLUMN p_pfx  NEW_VALUE pfx      NOPRINT
COLUMN p_cont NEW_VALUE cont_all NOPRINT
COLUMN p_con  NEW_VALUE con_name NOPRINT
SELECT CASE WHEN SYS_CONTEXT('USERENV','CON_NAME') = 'CDB$ROOT'
            THEN 'SOPULI_CDB_' ELSE 'SOPULI_' END        AS p_pfx,
       CASE WHEN SYS_CONTEXT('USERENV','CON_NAME') = 'CDB$ROOT'
            THEN ' CONTAINER = ALL' ELSE '' END          AS p_cont,
       SYS_CONTEXT('USERENV','CON_NAME')                 AS p_con
  FROM dual;
SET TERMOUT ON
PROMPT audit policies for container &con_name: &pfx.*

--------------------------------------------------------------------------------
-- 1. Audit every user-management statement, by anyone
--
--    Deliberately not restricted to the service account: the point is to see
--    all password changes, including the manual ones the tool is replacing.
--------------------------------------------------------------------------------
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM audit_unified_policies
   WHERE policy_name = '&pfx.POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE AUDIT POLICY &pfx.POL ACTIONS ALTER USER, CREATE USER, DROP USER&cont_all';
    DBMS_OUTPUT.PUT_LINE('created audit policy &pfx.POL');
  ELSE
    DBMS_OUTPUT.PUT_LINE('audit policy &pfx.POL already exists');
  END IF;

  SELECT COUNT(*) INTO l_cnt FROM audit_unified_enabled_policies
   WHERE policy_name = '&pfx.POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'AUDIT POLICY &pfx.POL';
    DBMS_OUTPUT.PUT_LINE('enabled &pfx.POL');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 2. Failed logons by the service account — what credential probing looks like
--------------------------------------------------------------------------------
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM audit_unified_policies
   WHERE policy_name = '&pfx.LOGON_POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE AUDIT POLICY &pfx.LOGON_POL ACTIONS LOGON&cont_all';
    DBMS_OUTPUT.PUT_LINE('created audit policy &pfx.LOGON_POL');
  END IF;
END;
/
AUDIT POLICY &pfx.LOGON_POL BY &svc_user WHENEVER NOT SUCCESSFUL;

--------------------------------------------------------------------------------
-- 3. Successful logons by the personal accounts, when a list is given
--
--    A DBA who acts as a person logs on through a proxy, DBA[person]. That
--    logon is the record that names the DBA (11_proxy_connect_probe.sql). A
--    BY list applies to the account that issues the statement, and the person
--    issues the logon. So the policy is enabled BY the person: BY the DBA
--    does not record the proxy logon (13_audit_coverage_probe.sql AC4).
--
--    Only the listed accounts. Enabled for every user, it would record every
--    session, connection pools included.
--
--    Every name is checked before anything is created or enabled.
--    DBMS_ASSERT.SCHEMA_NAME raises ORA-44001 for a name that is not an
--    account, so a typing error stops the script with nothing changed, instead
--    of enabling the names before it and not the names after it.
--
--    The list is read in upper case, with white space removed, because that
--    is how Oracle stores an unquoted account name. An account created with a
--    quoted lower-case name cannot be listed.
--------------------------------------------------------------------------------
DECLARE
  TYPE t_names IS TABLE OF VARCHAR2(128);
  l_list  VARCHAR2(4000) := REGEXP_REPLACE(UPPER('&persons'), '[[:space:]]');
  l_names t_names := t_names();
  l_name  VARCHAR2(128);
  l_pos   PLS_INTEGER;
  l_cnt   PLS_INTEGER;
BEGIN
  IF l_list IS NULL THEN
    DBMS_OUTPUT.PUT_LINE('no personal accounts given: &pfx.PERSON_LOGON_POL left as it is');
    RETURN;
  END IF;

  WHILE l_list IS NOT NULL LOOP
    l_pos := INSTR(l_list, ',');
    IF l_pos = 0 THEN
      l_name := l_list;
      l_list := NULL;
    ELSE
      l_name := SUBSTR(l_list, 1, l_pos - 1);
      l_list := SUBSTR(l_list, l_pos + 1);
    END IF;
    IF l_name IS NOT NULL THEN
      l_names.EXTEND;
      l_names(l_names.LAST) := DBMS_ASSERT.SCHEMA_NAME(l_name);
    END IF;
  END LOOP;

  SELECT COUNT(*) INTO l_cnt FROM audit_unified_policies
   WHERE policy_name = '&pfx.PERSON_LOGON_POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE AUDIT POLICY &pfx.PERSON_LOGON_POL ACTIONS LOGON&cont_all';
    DBMS_OUTPUT.PUT_LINE('created audit policy &pfx.PERSON_LOGON_POL');
  END IF;

  FOR i IN 1 .. l_names.COUNT LOOP
    SELECT COUNT(*) INTO l_cnt FROM audit_unified_enabled_policies
     WHERE policy_name = '&pfx.PERSON_LOGON_POL' AND entity_name = l_names(i)
       AND success = 'YES';
    IF l_cnt = 0 THEN
      EXECUTE IMMEDIATE 'AUDIT POLICY &pfx.PERSON_LOGON_POL BY '
        || DBMS_ASSERT.ENQUOTE_NAME(l_names(i), FALSE) || ' WHENEVER SUCCESSFUL';
      DBMS_OUTPUT.PUT_LINE('enabled &pfx.PERSON_LOGON_POL BY ' || l_names(i));
    ELSE
      DBMS_OUTPUT.PUT_LINE('&pfx.PERSON_LOGON_POL already enabled BY ' || l_names(i));
    END IF;
  END LOOP;
END;
/

--------------------------------------------------------------------------------
-- In CDB$ROOT only: drop the local policies an older copy of this script
-- created there
--
--    They record nothing in a PDB (AC8), so they only looked like a control.
--    This runs after sections 1 to 3, so a failure while creating the common
--    policies leaves the old ones in place: the root is never left with
--    neither. Only the two names the older script created: a policy an estate
--    added itself under another SOPULI_ name is left alone. NOAUDIT names each
--    account an enablement was made BY, for the reason 99_uninstall.sql
--    section 2 gives.
--------------------------------------------------------------------------------
BEGIN
  IF '&con_name' = 'CDB$ROOT' THEN
    FOR p IN (SELECT DISTINCT policy_name, entity_name
                FROM audit_unified_enabled_policies
               WHERE policy_name IN ('SOPULI_POL', 'SOPULI_LOGON_POL')) LOOP
      IF p.entity_name = 'ALL USERS' THEN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p.policy_name;
      ELSE
        EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p.policy_name
                       || ' BY ' || DBMS_ASSERT.ENQUOTE_NAME(p.entity_name, FALSE);
      END IF;
    END LOOP;
    FOR p IN (SELECT DISTINCT policy_name FROM audit_unified_policies
               WHERE policy_name IN ('SOPULI_POL', 'SOPULI_LOGON_POL')) LOOP
      EXECUTE IMMEDIATE 'DROP AUDIT POLICY ' || p.policy_name;
      DBMS_OUTPUT.PUT_LINE('dropped ' || p.policy_name || ' from CDB$ROOT: '
        || 'a policy created here without CONTAINER = ALL records nothing in a PDB');
    END LOOP;
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 4. Everyday queries
--
--    In CDB$ROOT, these read the root's trail only. CDB_UNIFIED_AUDIT_TRAIL
--    has every container's.
--
--    Whether a password leaks into any trail is release gate 2, a separate
--    probe: 02_password_leak_probe.sql, run in the positions
--    docs/design/04-testing.md §6 gives.
--------------------------------------------------------------------------------
SET LINESIZE 220
COLUMN dbusername  FORMAT A20
COLUMN object_name FORMAT A22
COLUMN client_identifier FORMAT A38
COLUMN action_name FORMAT A14

PROMPT --- all user-management statements, last 24h, whoever ran them
SELECT event_timestamp, dbusername, action_name, object_name,
       return_code, client_identifier
  FROM unified_audit_trail
 WHERE action_name IN ('ALTER USER','CREATE USER','DROP USER')
   AND event_timestamp > SYSTIMESTAMP - 1
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

PROMPT --- statements NOT made by the service account (i.e. manual changes)
SELECT event_timestamp, dbusername, action_name, object_name
  FROM unified_audit_trail
 WHERE action_name = 'ALTER USER'
   AND dbusername != UPPER('&svc_user')
   AND event_timestamp > SYSTIMESTAMP - 7
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

PROMPT --- failed logons by the service account
SELECT event_timestamp, dbusername, return_code, authentication_type
  FROM unified_audit_trail
 WHERE dbusername = UPPER('&svc_user')
   AND action_name = 'LOGON'
   AND return_code != 0
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

PROMPT --- proxy logons, last 7 days: DBPROXY_USERNAME is the DBA
SELECT event_timestamp, dbusername, dbproxy_username, return_code
  FROM unified_audit_trail
 WHERE action_name = 'LOGON'
   AND dbproxy_username IS NOT NULL
   AND event_timestamp > SYSTIMESTAMP - 7
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

--------------------------------------------------------------------------------
-- 5. One sopuli run, end to end
--
--    The tool calls DBMS_SESSION.SET_IDENTIFIER(<correlation_id>) on every
--    connection, so its UUID lands in UNIFIED_AUDIT_TRAIL.CLIENT_IDENTIFIER.
--    That is the join between the tool's JSON output, this trail, and the
--    vault's secret metadata. Take the id from the tool's output:
--
--      jq -r .invocation.correlation_id result.json
--------------------------------------------------------------------------------
-- SELECT event_timestamp, dbusername, action_name, object_name, return_code
--   FROM unified_audit_trail
--  WHERE client_identifier = '&correlation_id'
--  ORDER BY event_timestamp;

--------------------------------------------------------------------------------
-- 6. Oracle 11.2 fallback (no unified auditing)
--
--    AUDIT ALTER USER is a PRIVILEGE option; AUDIT USER is a STATEMENT option.
--    They are NOT equivalent, and the difference is not cosmetic. Privilege
--    auditing records statements executed by virtue of holding ALTER USER, so an
--    account changing its OWN password with IDENTIFIED BY ... REPLACE ...
--    (self-rotation, UC-1 Q6) exercises no privilege and may not be recorded.
--    Enable both where both exist, and check DBA_STMT_AUDIT_OPTS and
--    DBA_PRIV_AUDIT_OPTS separately -- one being set says nothing about the other.
--
--    Also: SQL_TEXT is only populated when AUDIT_TRAIL is 'DB,EXTENDED'. With a
--    plain 'DB' it is NULL for every statement ever executed, which reads as a
--    clean leak result and is not one.
--
--    On 23ai and later BOTH statements raise ORA-46401: traditional auditing is
--    desupported and no new configuration is accepted. Confirmed on 26ai Free
--    23.26.2.0.0. That is expected, not a failure -- only the unified path applies.
--------------------------------------------------------------------------------
-- AUDIT USER;                              -- statement option
-- AUDIT ALTER USER BY ACCESS;              -- privilege option
--
-- SELECT timestamp, username, action_name, obj_name, returncode, client_id
--   FROM dba_audit_trail
--  WHERE action_name LIKE '%USER%'
--    AND timestamp > SYSDATE - 1
--  ORDER BY timestamp DESC;
