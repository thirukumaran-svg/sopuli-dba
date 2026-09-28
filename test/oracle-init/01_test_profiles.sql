--------------------------------------------------------------------------------
-- sopuli-dba : test profiles
--
-- STATUS: runs. Confirmed against gvenzl/oracle-free on 26ai 23.26.2.0.0 --
-- SOPULI_LOCKOUT is present in a freshly started container, so the image does
-- execute this and the profiles below are real rather than aspirational.
--
-- Runs once at container init. Creates the profiles the test suite needs, so no
-- test has to assume anything pre-exists. Test *accounts* are created and dropped
-- per test under a per-run prefix — only the profiles live here.
--
-- Every statement is written to be safe on 11g XE through 26ai; anything a given
-- version rejects is caught and reported rather than aborting init.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON

-- 1. Lockout regression (04-testing.md §5). FAILED_LOGIN_ATTEMPTS is deliberately
--    low so a check-loop bug locks the account within a handful of iterations —
--    the test asserts it never does.
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_profiles
   WHERE profile = 'SOPULI_LOCKOUT' AND ROWNUM = 1;
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE PROFILE sopuli_lockout LIMIT '
                   || 'FAILED_LOGIN_ATTEMPTS 3 PASSWORD_LOCK_TIME 1/1440';
    DBMS_OUTPUT.PUT_LINE('created profile SOPULI_LOCKOUT');
  END IF;
END;
/

-- 2. Verify-function case. ora12c_strong_verify_function requires two of each
--    character class; the test pairs it with a policy that violates it and asserts
--    bounded regeneration plus a clear final error carrying the server message.
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_profiles
   WHERE profile = 'SOPULI_STRONG' AND ROWNUM = 1;
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE PROFILE sopuli_strong LIMIT '
                   || 'PASSWORD_VERIFY_FUNCTION ora12c_strong_verify_function';
    DBMS_OUTPUT.PUT_LINE('created profile SOPULI_STRONG');
  END IF;
EXCEPTION
  WHEN OTHERS THEN
    -- 11g has a different function name; the suite skips this case there.
    DBMS_OUTPUT.PUT_LINE('SOPULI_STRONG not created: ' || SQLERRM);
END;
/

-- 3. Password reuse. Asserts the tool never retries blindly on ORA-28007.
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_profiles
   WHERE profile = 'SOPULI_REUSE' AND ROWNUM = 1;
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE PROFILE sopuli_reuse LIMIT '
                   || 'PASSWORD_REUSE_MAX 5 PASSWORD_REUSE_TIME UNLIMITED';
    DBMS_OUTPUT.PUT_LINE('created profile SOPULI_REUSE');
  END IF;
END;
/

-- 4. Gradual password rollover (19.12+/21c+). Absent on older lines — its absence
--    is itself a test case: `--strategy rollover` must fail at PLAN time there.
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_profiles
   WHERE profile = 'SOPULI_ROLLOVER' AND ROWNUM = 1;
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE 'CREATE PROFILE sopuli_rollover LIMIT '
                   || 'PASSWORD_ROLLOVER_TIME 1/24';   -- one hour
    DBMS_OUTPUT.PUT_LINE('created profile SOPULI_ROLLOVER');
  END IF;
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('SOPULI_ROLLOVER not created (expected below 19.12): '
                         || SQLERRM);
END;
/
--------------------------------------------------------------------------------
-- 5. SELECT ON SYS.USER$, so the LCOUNT lockout guard can be exercised.
--
-- #86 made this an OPTIONAL grant, and the tool works without it -- `check`
-- still runs and says the guard is unavailable. But release gate 4 asserts that
-- checking a drifted account repeatedly never locks it, and the guard is the
-- thing that makes that true. Without this grant the gate would skip, which is
-- the one outcome a release gate must not have.
--
-- Granted to SYSTEM, which is SOPULI_TEST_ORACLE_USER's default. A lane
-- pointed at a different account has to make the grant itself, and the tests
-- skip rather than fail when it is missing. Hard-coded rather than substituted,
-- because an undefined `&` variable makes sqlplus prompt, and a prompt during
-- container init hangs the container.
--
-- Measured: SYSTEM does NOT hold this by default on 23ai -- reading SYS.USER$
-- as SYSTEM gives ORA-41900 -- so this is a real change to what the lane can
-- do, not a no-op.
--
-- Guarded, because the suite must stay green on versions where it fails.
--------------------------------------------------------------------------------
BEGIN
  -- CONTAINER=ALL first, because this script runs in CDB$ROOT and the suite
  -- connects to a PDB. Measured: the plain form lands in the root only --
  -- DBA_TAB_PRIVS shows the grant in CDB$ROOT and not in FREEPDB1 -- so the
  -- obvious statement grants a privilege nothing the suite does can use.
  -- Profiles are not like this: one created in the root is visible in the PDB,
  -- which is why sections 1 to 4 need no such clause and this does.
  EXECUTE IMMEDIATE 'GRANT SELECT ON SYS.USER$ TO SYSTEM CONTAINER=ALL';
  DBMS_OUTPUT.PUT_LINE('granted SELECT ON SYS.USER$ to SYSTEM (all containers)');
EXCEPTION
  WHEN OTHERS THEN
    BEGIN
      -- A non-CDB has no CONTAINER clause to give, and a PDB (oracle-19c, whose
      -- init runs there) cannot grant to ALL.
      EXECUTE IMMEDIATE 'GRANT SELECT ON SYS.USER$ TO SYSTEM';
      DBMS_OUTPUT.PUT_LINE('granted SELECT ON SYS.USER$ to SYSTEM (this container only)');
    EXCEPTION
      WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('SELECT ON SYS.USER$ not granted (' || SQLERRM
                          || '): the LCOUNT guard tests will skip');
    END;
END;
/

-- 6. Report what this container actually supports, so a test run can be read
--    against the capability matrix without guessing.
--
--    This is a PL/SQL block, not a query, for the same reason steps 2 and 4 are:
--    parts of it are unavailable on older lines and a reporting failure must
--    never abort container init. Two 11g constraints are load-bearing here and
--    were both confirmed against 11.2.0.2 (04-testing.md T1):
--      * LISTAGG(DISTINCT ...) is 19c+ — ORA-30482 below it, including on 18c.
--        Take the DISTINCT in a subquery instead.
--      * SYS_CONTEXT('USERENV','CON_NAME') raises ORA-02003 on a non-CDB.
DECLARE
  l_value VARCHAR2(200);
BEGIN
  FOR r IN (SELECT banner FROM v$version WHERE ROWNUM = 1) LOOP
    DBMS_OUTPUT.PUT_LINE('banner              : ' || r.banner);
  END LOOP;

  BEGIN
    SELECT SYS_CONTEXT('USERENV','CON_NAME') INTO l_value FROM dual;
  EXCEPTION
    WHEN OTHERS THEN
      l_value := 'n/a (non-CDB)';
  END;
  DBMS_OUTPUT.PUT_LINE('container           : ' || l_value);

  SELECT LISTAGG(profile, ', ') WITHIN GROUP (ORDER BY profile)
    INTO l_value
    FROM (SELECT DISTINCT profile FROM dba_profiles WHERE profile LIKE 'SOPULI%');
  DBMS_OUTPUT.PUT_LINE('profiles created    : ' || NVL(l_value, '(none)'));

  SELECT CASE WHEN EXISTS (SELECT 1 FROM dba_profiles
                            WHERE resource_name = 'PASSWORD_ROLLOVER_TIME')
              THEN 'yes' ELSE 'no' END
    INTO l_value
    FROM dual;
  DBMS_OUTPUT.PUT_LINE('rollover supported  : ' || l_value);
EXCEPTION
  WHEN OTHERS THEN
    -- Reporting is diagnostic only; never let it fail the init script.
    DBMS_OUTPUT.PUT_LINE('capability report incomplete: ' || SQLERRM);
END;
/

