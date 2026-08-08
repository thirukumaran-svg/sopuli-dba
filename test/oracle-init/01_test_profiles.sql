--------------------------------------------------------------------------------
-- sopuli-dba : test profiles
--
-- STATUS: DRAFT, never run.
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

-- 5. Report what this container actually supports, so a test run can be read
--    against the capability matrix without guessing.
SET LINESIZE 160
COLUMN feature FORMAT A34
COLUMN value   FORMAT A60

SELECT 'banner'                       AS feature, banner AS value FROM v$version WHERE ROWNUM = 1
UNION ALL
SELECT 'container', SYS_CONTEXT('USERENV','CON_NAME') FROM dual
UNION ALL
SELECT 'profiles created',
       LISTAGG(DISTINCT profile, ', ') WITHIN GROUP (ORDER BY profile)
  FROM dba_profiles WHERE profile LIKE 'SOPULI%'
UNION ALL
SELECT 'rollover supported',
       CASE WHEN EXISTS (SELECT 1 FROM dba_profiles
                          WHERE resource_name = 'PASSWORD_ROLLOVER_TIME')
            THEN 'yes' ELSE 'no' END
  FROM dual;
