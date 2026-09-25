--------------------------------------------------------------------------------
-- sopuli-dba : bare PASSWORD EXPIRE probe   (v1)
--
-- #525, `sopuli account expire-password`. Every UC-2 measurement so far is of
-- the SUFFIXED form, `IDENTIFIED BY "..." PASSWORD EXPIRE` (07, Q7). The verb
-- issues the BARE form -- `ALTER USER x PASSWORD EXPIRE`, no password at all --
-- and nothing has measured it. #525 lists what it needs, and this is that list:
--
--   E1  bare PASSWORD EXPIRE on an OPEN account: the resulting status
--   E2  the same statement again on the now-EXPIRED account: accepted silently,
--       or an error? (invariant 9: does the driver HAVE to read state first?)
--   E3  on EXPIRED(GRACE): a real change to EXPIRED, or a no-op? (#525 Q2)
--   E4  on a deliberate LOCKED: the resulting status; does it disturb the lock?
--   E5  on LOCKED(TIMED): the same
--   E6  on a rollover profile with the window CLOSED: the status
--   E7  on a rollover profile with the window OPEN: the status, and -- in the
--       login checks -- whether the OLD password still authenticates (#525 Q1,
--       option a)
--   E8  EXPIRE PASSWORD ROLLOVER PERIOD, THEN bare PASSWORD EXPIRE, window
--       open: does the old password die? (#525 Q1, option b)
--   E9  the other order -- bare PASSWORD EXPIRE, then EXPIRE PASSWORD ROLLOVER
--       PERIOD: is the close accepted on an EXPIRED & IN ROLLOVER account, and
--       does it still kill the old password?
--   E10 what the bare statement leaves in V$SQL and UNIFIED_AUDIT_TRAIL. It
--       carries no password, so this is a record of the DBA-side trail and not
--       a leak check.
--
-- This MEASURES and decides nothing. #525's questions are answered on the issue.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1,
-- as SYSTEM, 2026-09-25 -- three times, the last two identical and clean (the
-- first hit trap 6 below and is not counted). 21c, 18c, 11.2 and 19c UNRUN. On a
-- release with no rollover (18c, 11.2) section 5 reports ABSENT and the script
-- stops there; E1-E5 are written to run on every line, which is untried.
--
-- THROWAWAY DATABASES ONLY. Creates and drops accounts and a profile, locks
-- accounts, expires them, and plants known passwords.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, as SYSTEM, 2026-09-25
--
--   E1  OPEN -> EXPIRED. EXPIRY_DATE is set to the moment of the statement.
--       The login check with the unchanged password is ORA-28001: the bare form
--       does what the verb says, with no password in the statement.
--
--   E2  A second bare PASSWORD EXPIRE on an EXPIRED account is ACCEPTED
--       silently: no error, status EXPIRED, EXPIRY_DATE unchanged. So the
--       server gives no signal of a no-op, and `changed: false` (invariant 9)
--       can only come from reading ACCOUNT_STATUS first -- #463's shape exactly.
--
--   E3  EXPIRED(GRACE) -> EXPIRED, and EXPIRY_DATE moves from the end of the
--       grace period (+1 day) to now. A REAL change, not a no-op: during grace
--       the password still logs in, and after this it does not without a
--       change. So EXPIRED(GRACE) is NOT "already expired" for the verb -- the
--       same shape as #463's LOCKED(TIMED), and the same reason: a component
--       test that matched on the prefix EXPIRED would report a change that has
--       not happened as one that already had.
--       Incidentally: the grace-period login on 26ai sends ORA-28098 ("password
--       will expire within 1 days"), not ORA-28002 -- #322's finding, reproduced.
--
--   E4  LOCKED -> EXPIRED & LOCKED. The lock is untouched.
--
--   E5  LOCKED(TIMED) -> EXPIRED & LOCKED(TIMED). The timed lock is untouched.
--       E4 and E5 together: expiry and lock are independent components, and the
--       verb neither clears nor needs to care about either lock.
--
--   E6  Rollover profile, window CLOSED: OPEN -> EXPIRED. Plain, no IN ROLLOVER
--       component, and the password is ORA-28001. A rollover PROFILE alone
--       changes nothing; only an open WINDOW does.
--
--   E7  Window OPEN, bare PASSWORD EXPIRE (#525 Q1, option a):
--       OPEN & IN ROLLOVER -> EXPIRED & IN ROLLOVER, and **the OLD password
--       still authenticates** -- ORA-28001 for both old and new. The same
--       finding as 07's Q7 for the suffixed form, now on the bare one: expiry
--       does not end a rollover window, and during it the old password is a
--       live way to set the next one.
--
--   E8  Window OPEN, EXPIRE PASSWORD ROLLOVER PERIOD then bare PASSWORD EXPIRE
--       (option b): OPEN & IN ROLLOVER -> OPEN -> EXPIRED. Old password
--       ORA-01017 (dead), new ORA-28001. Option b works as the reset's default
--       does, with no IDENTIFIED BY in the session.
--
--   E9  The other order -- bare PASSWORD EXPIRE, then the close: the close is
--       ACCEPTED on an EXPIRED & IN ROLLOVER account and leaves plain EXPIRED.
--       Old ORA-01017, new ORA-28001. So the order does not matter to the
--       outcome on this release; both reach the same state.
--
--   E10 No V$SQL cursor is retained for the bare DDL, matching what 02 found
--       for the password-bearing form. UNIFIED_AUDIT_TRAIL returned no rows
--       because the tier-1 stack audits no ALTER USER, which is "not audited",
--       not "not recorded". Nothing here is a leak question; no password is in
--       the statement.
--
--
-- HOW TO RUN
--   07_lock_and_rollover_probe.sql's HOW TO RUN and its FOUR TRAPS apply
--   unchanged, and are not repeated here. v1's first run added a sixth,
--   recorded here because this file is where it bit:
--
--   - **A PROMPT line must not contain `&`.** `PROMPT ... OPEN & IN ROLLOVER`
--     is a substitution variable named `IN`; sqlplus asked for its value and
--     read the NEXT SCRIPT LINE as the answer. One casualty was a WHENEVER
--     SQLERROR EXIT FAILURE, so the rest of the run went on fail-open. Status
--     values with ` & ` are written with "and" in every PROMPT here.
-- In short: copy, set admin_pwd in the
--   copy, pipe it in, delete the copy -- never substitute a password with a
--   command-line tool, because that puts it in argv (invariant 1).
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < /tmp/probe.sql
--
--   **The login checks are separate invocations**, for 07's fourth trap: every
--   interesting account here ends EXPIRED, and an expired-password CONNECT
--   prompts for a new one and eats the rest of the script. Run each as its own
--   invocation with the CONNECT on stdin; the blank lines answer the change
--   prompt so it fails cleanly instead of hanging:
--
--     printf 'CONNECT %s/"%s"@%s\n\n\n' <acct> <pw> //localhost:1521/FREEPDB1 \
--       | MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 sqlplus -S /nolog
--
--   ORA-28001 means the password AUTHENTICATED and is merely expired;
--   ORA-01017 means it is dead. The checks, each with the password to try:
--
--     sopuli_ex_open    p1                expect 28001 (E1 did expire it)
--     sopuli_ex_roll_a  p1 (old), p2 (new) option a: is p1 still live?
--     sopuli_ex_roll_b  p1 (old), p2 (new) option b: is p1 dead?
--     sopuli_ex_roll_c  p1 (old), p2 (new) E9's order
--
--   printf is a shell builtin, so the password in its arguments reaches no
--   process list; `docker exec` receives it on stdin only.
--
--   Section 8 leaves every account in place for those checks. Drop them after:
--   section 9's commented block does it.
--------------------------------------------------------------------------------

DEFINE tns        = //localhost:1521/FREEPDB1
DEFINE admin_user = system
DEFINE admin_pwd  = CHANGEME_ADMIN_PASSWORD

-- Known passwords, alphanumeric and 12 bytes for 07's reasons.
DEFINE p1         = Aq8xProbeOne
DEFINE p2         = Bq8xProbeTwo
DEFINE pwrong     = Zq9xNotThePw

SET LINESIZE 200
SET PAGESIZE 1000
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

COLUMN username        FORMAT A18
COLUMN account_status  FORMAT A32
COLUMN profile         FORMAT A20
COLUMN expiry_date     FORMAT A19
COLUMN sql_text        FORMAT A70
COLUMN action_name     FORMAT A14
COLUMN dbusername      FORMAT A10

WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT ================================================================
PROMPT  sopuli-dba #525 probe v1: bare PASSWORD EXPIRE
PROMPT ================================================================
SELECT banner_full FROM v$version;
SELECT SYS_CONTEXT('USERENV','CON_NAME') AS container FROM dual;

--------------------------------------------------------------------------------
-- 0. Setup. Every account is dropped and recreated, and the grace profile is
--    the probe's own: nothing in test/oracle-init creates one, and a test
--    profile with a one-second lifetime is not something the suite should find.
--
--    No password goes into either block, which is why they may be PL/SQL.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 0. Setup ====
BEGIN
  FOR r IN (SELECT username FROM dba_users WHERE username LIKE 'SOPULI\_EX\_%' ESCAPE '\') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || r.username || ' CASCADE';
    DBMS_OUTPUT.PUT_LINE('dropped a pre-existing ' || r.username);
  END LOOP;
  FOR r IN (SELECT DISTINCT profile FROM dba_profiles WHERE profile = 'SOPULI_PROBE_GRACE') LOOP
    EXECUTE IMMEDIATE 'DROP PROFILE sopuli_probe_grace';
    DBMS_OUTPUT.PUT_LINE('dropped a pre-existing SOPULI_PROBE_GRACE');
  END LOOP;
END;
/
-- A one-second lifetime and a one-day grace: the first login after a second
-- moves the account into EXPIRED(GRACE), which is the state E3 needs.
CREATE PROFILE sopuli_probe_grace LIMIT PASSWORD_LIFE_TIME 1/86400 PASSWORD_GRACE_TIME 1;

CREATE USER sopuli_ex_open   IDENTIFIED BY "&p1";
CREATE USER sopuli_ex_grace  IDENTIFIED BY "&p1" PROFILE sopuli_probe_grace;
CREATE USER sopuli_ex_locked IDENTIFIED BY "&p1";
CREATE USER sopuli_ex_timed  IDENTIFIED BY "&p1" PROFILE sopuli_lockout;
GRANT CREATE SESSION TO sopuli_ex_open, sopuli_ex_grace, sopuli_ex_locked, sopuli_ex_timed;
PROMPT created sopuli_ex_open, _grace, _locked, _timed, all with p1

--------------------------------------------------------------------------------
-- 1. E1 and E2 -- an OPEN account, expired twice.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 1. E1: bare PASSWORD EXPIRE on an OPEN account ====
SELECT username, account_status, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username = 'SOPULI_EX_OPEN';
ALTER USER sopuli_ex_open PASSWORD EXPIRE;
PROMPT issued ALTER USER sopuli_ex_open PASSWORD EXPIRE
SELECT username, account_status, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username = 'SOPULI_EX_OPEN';

PROMPT
PROMPT ==== 1. E2: the same statement again, on the now-EXPIRED account ====
WHENEVER SQLERROR CONTINUE NONE
ALTER USER sopuli_ex_open PASSWORD EXPIRE;
PROMPT no ORA- above means ACCEPTED on an already-expired account
WHENEVER SQLERROR EXIT FAILURE
SELECT username, account_status, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username = 'SOPULI_EX_OPEN';

--------------------------------------------------------------------------------
-- 2. E3 -- EXPIRED(GRACE).
--
-- The status only moves into grace at a LOGIN after the lifetime has passed, so
-- this sleeps past the one-second lifetime and logs in once. A grace-period
-- login SUCCEEDS with a warning -- which is #309's whole lesson, and why this
-- CONNECT is safe where an expired one would not be. #322 found 26ai does not
-- send ORA-28002 for it; whatever it does send is printed, not assumed.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 2. E3: bare PASSWORD EXPIRE on EXPIRED(GRACE) ====
EXEC DBMS_SESSION.SLEEP(3)
WHENEVER SQLERROR CONTINUE NONE
CONNECT sopuli_ex_grace/"&p1"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT after the grace-period login, expecting EXPIRED(GRACE):
SELECT username, account_status, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username = 'SOPULI_EX_GRACE';
ALTER USER sopuli_ex_grace PASSWORD EXPIRE;
PROMPT issued ALTER USER sopuli_ex_grace PASSWORD EXPIRE
SELECT username, account_status, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username = 'SOPULI_EX_GRACE';

--------------------------------------------------------------------------------
-- 3. E4 -- a deliberate LOCKED.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 3. E4: bare PASSWORD EXPIRE on a deliberate LOCKED ====
ALTER USER sopuli_ex_locked ACCOUNT LOCK;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_LOCKED';
ALTER USER sopuli_ex_locked PASSWORD EXPIRE;
PROMPT issued ALTER USER sopuli_ex_locked PASSWORD EXPIRE
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_LOCKED';

--------------------------------------------------------------------------------
-- 4. E5 -- LOCKED(TIMED). SOPULI_LOCKOUT is three failures and a one-minute
--    lock, so this reads the status immediately rather than after a pause.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 4. E5: bare PASSWORD EXPIRE on LOCKED(TIMED) ====
WHENEVER SQLERROR CONTINUE NONE
CONNECT sopuli_ex_timed/"&pwrong"@&tns
CONNECT sopuli_ex_timed/"&pwrong"@&tns
CONNECT sopuli_ex_timed/"&pwrong"@&tns
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_TIMED';
ALTER USER sopuli_ex_timed PASSWORD EXPIRE;
PROMPT issued ALTER USER sopuli_ex_timed PASSWORD EXPIRE
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_TIMED';

--------------------------------------------------------------------------------
-- 5. Rollover gate. Raises rather than substitutes, for 07's fifth trap.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 5. rollover capability ====
DECLARE
  l_n PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_n
    FROM dba_profiles WHERE profile = 'SOPULI_ROLLOVER' AND ROWNUM = 1;
  IF l_n = 0 THEN
    raise_application_error(-20001,
      'ABSENT: no SOPULI_ROLLOVER profile on this release. Sections 6-8 are '
      || 'ABSENT rather than clean, and E1-E5 above still stand.');
  END IF;
  DBMS_OUTPUT.PUT_LINE('SOPULI_ROLLOVER present, continuing into E6');
END;
/

--------------------------------------------------------------------------------
-- 6. E6-E9 -- the rollover profile.
--
-- Every baseline starts with the window CLOSED, for 07's v1 lesson: CREATE USER
-- on a rollover profile with p1 is not a window, but it is proven plain OPEN
-- before anything else happens, and then IDENTIFIED BY p2 opens one on purpose.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 6. rollover accounts: baseline ====
CREATE USER sopuli_ex_roll_z IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_ex_roll_a IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_ex_roll_b IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_ex_roll_c IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
GRANT CREATE SESSION TO sopuli_ex_roll_z, sopuli_ex_roll_a, sopuli_ex_roll_b, sopuli_ex_roll_c;
PROMPT baseline, every one must read plain OPEN:
SELECT username, account_status, profile FROM dba_users
 WHERE username LIKE 'SOPULI\_EX\_ROLL\_%' ESCAPE '\' ORDER BY username;

PROMPT
PROMPT ==== 6. E6: window CLOSED, bare PASSWORD EXPIRE ====
ALTER USER sopuli_ex_roll_z PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_ROLL_Z';

PROMPT
PROMPT ==== 6. opening a window on _a, _b and _c: IDENTIFIED BY p2 ====
ALTER USER sopuli_ex_roll_a IDENTIFIED BY "&p2";
ALTER USER sopuli_ex_roll_b IDENTIFIED BY "&p2";
ALTER USER sopuli_ex_roll_c IDENTIFIED BY "&p2";
PROMPT each must read OPEN and IN ROLLOVER:
SELECT username, account_status FROM dba_users
 WHERE username IN ('SOPULI_EX_ROLL_A','SOPULI_EX_ROLL_B','SOPULI_EX_ROLL_C') ORDER BY username;

PROMPT
PROMPT ==== 6. E7 (option a): window OPEN, bare PASSWORD EXPIRE ====
ALTER USER sopuli_ex_roll_a PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_ROLL_A';

PROMPT
PROMPT ==== 6. E8 (option b): close, THEN bare PASSWORD EXPIRE ====
ALTER USER sopuli_ex_roll_b EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT after the close:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_ROLL_B';
ALTER USER sopuli_ex_roll_b PASSWORD EXPIRE;
PROMPT after the expire:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_ROLL_B';

PROMPT
PROMPT ==== 6. E9: bare PASSWORD EXPIRE, THEN close ====
ALTER USER sopuli_ex_roll_c PASSWORD EXPIRE;
PROMPT after the expire:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_ROLL_C';
WHENEVER SQLERROR CONTINUE NONE
ALTER USER sopuli_ex_roll_c EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT no ORA- above means the close was ACCEPTED on an EXPIRED and IN ROLLOVER account
WHENEVER SQLERROR EXIT FAILURE
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_EX_ROLL_C';

--------------------------------------------------------------------------------
-- 7. E10 -- what the bare statement leaves behind. No password is in it, so
--    this is the DBA-side trail. UNIFIED_AUDIT_TRAIL is only populated if a
--    policy audits ALTER USER on this database (01_audit_policy.sql); an empty
--    result here is "not audited", not "not recorded".
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 7. E10: V$SQL and UNIFIED_AUDIT_TRAIL ====
SELECT sql_text FROM v$sql
 WHERE UPPER(sql_text) LIKE 'ALTER USER SOPULI\_EX\_%PASSWORD EXPIRE%' ESCAPE '\'
 ORDER BY sql_text;
PROMPT no rows above means no cursor was retained for the bare DDL
SELECT dbusername, action_name, SUBSTR(sql_text,1,70) AS sql_text
  FROM unified_audit_trail
 WHERE action_name = 'ALTER USER'
   AND UPPER(sql_text) LIKE '%SOPULI\_EX\_%' ESCAPE '\'
   AND event_timestamp > SYSTIMESTAMP - INTERVAL '10' MINUTE
 ORDER BY event_timestamp;

--------------------------------------------------------------------------------
-- 8. Summary of every account before the separate login checks.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 8. every probe account, as left for the login checks ====
SELECT username, account_status, profile FROM dba_users
 WHERE username LIKE 'SOPULI\_EX\_%' ESCAPE '\' ORDER BY username;
PROMPT
PROMPT the accounts are LEFT IN PLACE. Run the login checks in HOW TO RUN, then
PROMPT section 9 below.

--------------------------------------------------------------------------------
-- 9. Cleanup, run separately after the login checks.
--
-- BEGIN
--   FOR r IN (SELECT username FROM dba_users WHERE username LIKE 'SOPULI\_EX\_%' ESCAPE '\') LOOP
--     EXECUTE IMMEDIATE 'DROP USER ' || r.username || ' CASCADE';
--   END LOOP;
--   EXECUTE IMMEDIATE 'DROP PROFILE sopuli_probe_grace';
-- END;
-- /
--------------------------------------------------------------------------------
