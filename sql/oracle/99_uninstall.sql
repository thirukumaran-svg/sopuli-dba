--------------------------------------------------------------------------------
-- sopuli-dba : uninstall
--
-- STATUS: confirmed on 26ai Free 23.26.2.0.0 (2026-08-26) against a COMMON
--         install, with keep_audit=Y and with keep_audit=N. The account and all
--         8 grants were removed, and the ALTER USER audit history survived the
--         drop. Also run against a PDB install with both parameters passed
--         (`ACME_SVC N` -- deliberately NOT the default name, because a run
--         using the default cannot tell whether the parameter was honoured or
--         simply ignored).
--         Confirmed on 21c XE 21.3.0.0.0 (2026-09-08, #380) through
--         tests/driver/test_oracle_install_script.py, both keep_audit
--         settings.
--         Confirmed on 18c XE 18.4.0.0.0 (2026-09-08, #381), same route.
--         Untried on 19c and 11.2.
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
--------------------------------------------------------------------------------
-- Parameters
--
--   @99_uninstall.sql [svc_user] [keep_audit]
--
--   1 svc_user     the account to drop. Defaults to the COMMON name; pass
--                  SOPULI_SVC for a NONCDB or PDB install.
--   2 keep_audit   Y leaves the audit policies in place, which is the default
--                  and usually right: auditing ALTER USER is worth having
--                  whether or not this tool is installed.
--
-- The zero-row SELECT is not decoration: SQL*Plus PROMPTS for an `&1` that was
-- never supplied, and a prompt in a piped run reads the next line of the script
-- as its answer. `COLUMN n NEW_VALUE n` defines the missing positions as empty
-- without asking. 00_install.sql's parameter block has the long version.
--
-- Read while SQLERROR still EXITs. The uninstall proper runs under CONTINUE, so
-- it can finish past a failure -- but a parameter that failed to resolve would
-- leave `&svc_user` undefined, and the prompt that follows would eat the script.
--------------------------------------------------------------------------------
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET TERMOUT OFF
COLUMN 1 NEW_VALUE 1
COLUMN 2 NEW_VALUE 2
SELECT NULL AS "1", NULL AS "2" FROM dual WHERE 1 = 0;
COLUMN p_user NEW_VALUE svc_user   NOPRINT
COLUMN p_keep NEW_VALUE keep_audit NOPRINT
SELECT NVL('&1', 'C##SOPULI_SVC') AS p_user,
       NVL('&2', 'Y')             AS p_keep
  FROM dual;
SET TERMOUT ON

WHENEVER SQLERROR CONTINUE

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
    -- NOAUDIT must name the same principal the AUDIT named. An unqualified
    -- `NOAUDIT POLICY p` does NOT lift an enablement made `BY <user>` -- it
    -- reports success and leaves the policy enabled, and the DROP below then
    -- fails with ORA-46361. 01_audit_policy.sql enables sopuli_logon_pol
    -- `BY &svc_user`, so this is the ordinary case rather than a corner.
    --
    -- `entity_name = 'ALL USERS'` is how the view spells a global enablement;
    -- anything else is a real account and has to be named back.
    FOR p IN (SELECT DISTINCT policy_name, entity_name
                FROM audit_unified_enabled_policies
               WHERE policy_name IN ('SOPULI_POL','SOPULI_LOGON_POL')) LOOP
      IF p.entity_name = 'ALL USERS' THEN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p.policy_name;
      ELSE
        EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p.policy_name
                       || ' BY ' || p.entity_name;
      END IF;
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
