--------------------------------------------------------------------------------
-- sopuli-dba : uninstall
--
-- STATUS: confirmed on 26ai Free 23.26.2.0.0 (2026-08-26) against a COMMON
--         install, with keep_audit=Y and with keep_audit=N. The account and all
--         8 grants were removed, and the ALTER USER audit history survived the
--         drop. NEVER executed against NONCDB / PDB installs. Untried on 19c,
--         21c and 11.2.
--
-- Removes the service account and the audit policies. Does NOT change any
-- application account's password — whatever the tool last applied stays in
-- place. Make sure those passwords are retrievable from the vault before you
-- run this, because afterwards nothing here can set them again.
--
-- Run in the same container as the install. For a COMMON install, run in
-- CDB$ROOT.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON
SET DEFINE ON
SET VERIFY OFF
WHENEVER SQLERROR CONTINUE

DEFINE svc_user   = C##SOPULI_SVC     -- or SOPULI_SVC
DEFINE keep_audit = Y                 -- Y = leave the audit policies in place

--------------------------------------------------------------------------------
-- 1. The account. Dropping it removes every grant with it.
--------------------------------------------------------------------------------
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = UPPER('&svc_user');
  IF l_cnt > 0 THEN
    EXECUTE IMMEDIATE 'DROP USER &svc_user CASCADE';
    DBMS_OUTPUT.PUT_LINE('dropped &svc_user (ALTER USER grant gone with it)');
  ELSE
    DBMS_OUTPUT.PUT_LINE('&svc_user does not exist');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 2. Audit policies
--
--    Default is to KEEP them. Auditing ALTER USER is worth having whether or not
--    this tool is installed, and removing an audit policy during a cleanup is
--    the kind of thing that looks bad in a review later.
--------------------------------------------------------------------------------
BEGIN
  IF UPPER('&keep_audit') = 'Y' THEN
    DBMS_OUTPUT.PUT_LINE('leaving audit policies SOPULI_POL / SOPULI_LOGON_POL in place');
  ELSE
    FOR p IN (SELECT DISTINCT policy_name FROM audit_unified_enabled_policies
               WHERE policy_name IN ('SOPULI_POL','SOPULI_LOGON_POL')) LOOP
      EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p.policy_name;
    END LOOP;
    FOR p IN (SELECT DISTINCT policy_name FROM audit_unified_policies
               WHERE policy_name IN ('SOPULI_POL','SOPULI_LOGON_POL')) LOOP
      EXECUTE IMMEDIATE 'DROP AUDIT POLICY ' || p.policy_name;
      DBMS_OUTPUT.PUT_LINE('dropped audit policy ' || p.policy_name);
    END LOOP;
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 3. Verify nothing is left
--------------------------------------------------------------------------------
PROMPT --- should return no rows
SELECT username FROM dba_users WHERE username = UPPER('&svc_user');

SELECT grantee, privilege FROM dba_sys_privs WHERE grantee = UPPER('&svc_user');

SELECT grantee, owner, table_name, privilege FROM dba_tab_privs
 WHERE grantee = UPPER('&svc_user');

PROMPT --- audit policies still present (both if keep_audit=Y, none if N)
SELECT DISTINCT policy_name FROM audit_unified_policies
 WHERE policy_name IN ('SOPULI_POL','SOPULI_LOGON_POL');

PROMPT --- audit history is retained in UNIFIED_AUDIT_TRAIL regardless
SELECT COUNT(*) AS retained_alter_user_events
  FROM unified_audit_trail
 WHERE action_name = 'ALTER USER';
