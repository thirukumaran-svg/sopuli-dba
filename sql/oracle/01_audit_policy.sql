--------------------------------------------------------------------------------
-- sopuli-dba : auditing
--
-- STATUS: DRAFT, never executed.
--
-- The service account holds ALTER USER, which has no object scope. Unified
-- auditing is therefore not housekeeping — it is the compensating control for
-- the privilege model. Enable it before the first rotation.
--
-- Run in the same container as 00_install.sql. For a COMMON install, run in
-- CDB$ROOT.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON
SET DEFINE ON
DEFINE svc_user = C##SOPULI_SVC     -- or SOPULI_SVC for NONCDB / PDB installs

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
   WHERE policy_name = 'SOPULI_POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE AUDIT POLICY sopuli_pol ACTIONS ALTER USER, CREATE USER, DROP USER';
    DBMS_OUTPUT.PUT_LINE('created audit policy SOPULI_POL');
  ELSE
    DBMS_OUTPUT.PUT_LINE('audit policy SOPULI_POL already exists');
  END IF;

  SELECT COUNT(*) INTO l_cnt FROM audit_unified_enabled_policies
   WHERE policy_name = 'SOPULI_POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'AUDIT POLICY sopuli_pol';
    DBMS_OUTPUT.PUT_LINE('enabled SOPULI_POL');
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
   WHERE policy_name = 'SOPULI_LOGON_POL';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE AUDIT POLICY sopuli_logon_pol ACTIONS LOGON';
    DBMS_OUTPUT.PUT_LINE('created audit policy SOPULI_LOGON_POL');
  END IF;
END;
/
AUDIT POLICY sopuli_logon_pol BY &svc_user WHENEVER NOT SUCCESSFUL;

--------------------------------------------------------------------------------
-- 3. RELEASE GATE: does the password leak into any trail?
--
--    Rotate a throwaway account with a known password, then run these. Any row
--    returned is a finding that belongs in the README. Repeat on every major
--    version claimed as supported — do not assume Oracle's redaction behaviour.
--------------------------------------------------------------------------------
-- DEFINE probe = 'ReplaceWithTheActualTestPassword'
--
-- SELECT sql_id, sql_text FROM v$sql
--  WHERE sql_text LIKE '%&probe%';
--
-- SELECT event_timestamp, dbusername, action_name, sql_text
--   FROM unified_audit_trail
--  WHERE sql_text LIKE '%&probe%';
--
-- On the server:
--   grep -R '<probe>' $ORACLE_BASE/diag/rdbms/*/*/trace/ 2>/dev/null

--------------------------------------------------------------------------------
-- 4. Everyday queries
--------------------------------------------------------------------------------
SET LINESIZE 220
COLUMN dbusername  FORMAT A20
COLUMN object_name FORMAT A22
COLUMN client_id   FORMAT A38
COLUMN action_name FORMAT A14

PROMPT --- all user-management statements, last 24h, whoever ran them ---
SELECT event_timestamp, dbusername, action_name, object_name,
       return_code, client_id
  FROM unified_audit_trail
 WHERE action_name IN ('ALTER USER','CREATE USER','DROP USER')
   AND event_timestamp > SYSTIMESTAMP - 1
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

PROMPT --- statements NOT made by the service account (i.e. manual changes) ---
SELECT event_timestamp, dbusername, action_name, object_name
  FROM unified_audit_trail
 WHERE action_name = 'ALTER USER'
   AND dbusername != UPPER('&svc_user')
   AND event_timestamp > SYSTIMESTAMP - 7
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

PROMPT --- failed logons by the service account ---
SELECT event_timestamp, dbusername, return_code, authentication_type
  FROM unified_audit_trail
 WHERE dbusername = UPPER('&svc_user')
   AND action_name = 'LOGON'
   AND return_code != 0
 ORDER BY event_timestamp DESC
 FETCH FIRST 50 ROWS ONLY;

--------------------------------------------------------------------------------
-- 5. One sopuli run, end to end
--
--    The tool calls DBMS_SESSION.SET_IDENTIFIER(<correlation_id>) on every
--    connection, so its UUID lands in UNIFIED_AUDIT_TRAIL.CLIENT_ID. That is the
--    join between the tool's JSON output, this trail, and the vault's secret
--    metadata. Take the id from the tool's output:
--
--      jq -r .invocation.correlation_id result.json
--------------------------------------------------------------------------------
-- SELECT event_timestamp, dbusername, action_name, object_name, return_code
--   FROM unified_audit_trail
--  WHERE client_id = '&correlation_id'
--  ORDER BY event_timestamp;

--------------------------------------------------------------------------------
-- 6. Oracle 11.2 fallback (no unified auditing)
--------------------------------------------------------------------------------
-- AUDIT ALTER USER, CREATE USER, DROP USER;
--
-- SELECT timestamp, username, action_name, obj_name, returncode, client_id
--   FROM dba_audit_trail
--  WHERE action_name LIKE '%USER%'
--    AND timestamp > SYSDATE - 1
--  ORDER BY timestamp DESC;
