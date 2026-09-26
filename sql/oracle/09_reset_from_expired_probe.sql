--------------------------------------------------------------------------------
-- sopuli-dba : setting a password on an EXPIRED rollover account   (v1)
--
-- #529. UC-2 sec.4.3 refuses a SEEN reset of any account whose profile grants a
-- rollover window, for 07's Q7: `IDENTIFIED BY ... PASSWORD EXPIRE` on an OPEN
-- account leaves the old password live (ORA-28001) for the length of the
-- window. But UC-2's motivating case is an account that is already EXPIRED, and
-- #527's guide work saw a plain `IDENTIFIED BY` on an EXPIRED account open no
-- window at all. Whether the refusal is turning away the reset UC-2 exists for
-- is a question only a login can answer, and this is that list:
--
--   R1  from EXPIRED: IDENTIFIED BY p3 -- the status, and a login with p1 (the
--       password it expired with) and p3
--   R2  from EXPIRED: IDENTIFIED BY p3 PASSWORD EXPIRE (the seen form) -- the
--       same questions. This is the one sec.4.3 turns on
--   R3  from EXPIRED: R2, then EXPIRE PASSWORD ROLLOVER PERIOD -- the seen
--       reset's full shape if the refusal lifted, since the driver closes the
--       window after the set on both paths
--   R4  from EXPIRED and IN ROLLOVER (a window open, then a bare expiry): R1's
--       statement -- a login with p1 (pre-window), p2 (window) and p3
--   R5  from EXPIRED and IN ROLLOVER: R2's statement
--   R6  from EXPIRED and IN ROLLOVER: R3's pair
--   R7  from EXPIRED(GRACE), reached on a grace profile and then moved to the
--       rollover one: whether the move keeps the status, then R1's statement
--   R8  the same start, R2's statement
--   C1  CONTROL, from OPEN: R1's statement. Must open a window with p1 live, or
--       nothing below means what it says (07 Q6 step 1)
--   C2  CONTROL, from OPEN: R2's statement. Must reproduce 07 Q7 -- p1
--       ORA-28001 -- or the login method cannot see the thing it is looking for
--
-- This MEASURES and decides nothing. Whether sec.4.3's refusal narrows is #541.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1,
-- as SYSTEM, 2026-09-26 -- twice, statuses and login results identical, the
-- only difference the second run's setup dropping the first run's accounts.
-- Run on 21c XE 21.3.0.0.0 (gvenzl/oracle-xe:21-slim), XEPDB1, as SYSTEM,
-- 2026-09-26 (#461) -- twice, and identical to 26ai in every status and every
-- login check in the results table; the setup's grace-period logins send a
-- different warning code (RESULTS). 18c and 11.2 have no rollover and stop at section 0. 19c UNRUN.
--
-- THROWAWAY DATABASES ONLY. Creates and drops accounts and a profile, expires
-- them, and plants known passwords.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, as SYSTEM, 2026-09-26
--
--   Status after the statement, then each password's login. ORA-01017 is dead,
--   ORA-28001 authenticated and expired, "ok" authenticated.
--
--     start                   statement               status                  p1     p2     p3
--     EXPIRED                 R1 IDENTIFIED BY        OPEN                    01017  -      ok
--     EXPIRED                 R2 ... PASSWORD EXPIRE  EXPIRED                 01017  -      28001
--     EXPIRED                 R3 R2, then close       EXPIRED, then EXPIRED   01017  -      28001
--     EXPIRED and IN ROLLOVER R4 IDENTIFIED BY        OPEN                    01017  01017  ok
--     EXPIRED and IN ROLLOVER R5 ... PASSWORD EXPIRE  EXPIRED                 01017  01017  28001
--     EXPIRED and IN ROLLOVER R6 R5, then close       EXPIRED, then EXPIRED   01017  01017  28001
--     EXPIRED(GRACE)          R7 IDENTIFIED BY        OPEN and IN ROLLOVER    ok     -      ok
--     EXPIRED(GRACE)          R8 ... PASSWORD EXPIRE  EXPIRED and IN ROLLOVER 28001  -      28001
--     OPEN (control C1)          IDENTIFIED BY        OPEN and IN ROLLOVER    ok     -      ok
--     OPEN (control C2)          ... PASSWORD EXPIRE  EXPIRED and IN ROLLOVER 28001  -      28001
--
--   Both controls reproduce 07: C1 is Q6's step 1 and C2 is Q7. So the method
--   sees a live old password where there is one, and the rows above it are a
--   difference between start states rather than an artefact of the check.
--
--   From EXPIRED, with or without a window already open, a password set by
--   either form opens NO window, and every earlier password is dead -- the
--   status agrees with the logins this time. That includes p1 on the W rows,
--   the pre-window password 08's E7 found still answering ORA-28001 before the
--   set. The seen form leaves exactly one live password, the new one, expired.
--   The close after it (R3, R6) is accepted and changes nothing, as with no
--   window open anywhere else (07 Q6 step 3).
--
--   EXPIRED(GRACE) is NOT expired for this purpose: it behaves as OPEN does. A
--   window opens, and on the seen form the old password answers ORA-28001, which
--   is 07's Q7 exposure exactly. So the start state that matters is whether the
--   password still authenticates, not whether ACCOUNT_STATUS begins with
--   EXPIRED -- the same prefix trap 08's E3 found for the bare expiry.
--
--   21c XE 21.3.0.0.0, XEPDB1, 2026-09-26: the table above holds unchanged,
--   every row, on both runs -- statuses from the script, logins as separate
--   invocations. Both controls reproduce 07 on 21c too. One difference outside
--   the question: the grace-period logins in section 2 send ORA-28002 on 21c,
--   where 26ai sends ORA-28098 (08's E3, #322). The resulting EXPIRED(GRACE)
--   status is the same.
--
--   G was reached by a login in grace on the probe's own profile and then
--   ALTER USER ... PROFILE sopuli_rollover. The move kept EXPIRED(GRACE) and the
--   expiry date unchanged. An account that reaches grace on a rollover profile
--   by ageing was not tried: it would take at least the profile's lifetime.
--
--
-- HOW TO RUN
--   07_lock_and_rollover_probe.sql's HOW TO RUN and its FOUR TRAPS apply
--   unchanged, and so does 08's sixth: no `&` in a PROMPT, so every status with
--   ` & ` is written with "and" below. In short: copy, set admin_pwd in the copy,
--   pipe it in, delete the copy -- never substitute a password with a
--   command-line tool, because that puts it in argv (invariant 1).
--
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < /tmp/probe.sql
--
--   **The login checks are separate invocations**, for 07's fourth trap: most
--   accounts here end EXPIRED, and an expired-password CONNECT prompts for a new
--   one and eats the rest of a script. Run each as its own invocation with the
--   CONNECT on stdin; the blank lines answer the change prompt so it fails
--   cleanly instead of hanging:
--
--     printf 'CONNECT %s/"%s"@%s\n\n\n' <acct> <pw> //localhost:1521/FREEPDB1 \
--       | MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 sqlplus -S /nolog
--
--   ORA-28001 means the password AUTHENTICATED and is merely expired; ORA-01017
--   means it is dead; no error means it authenticated and is not expired. The
--   checks, each account with every password it has ever had:
--
--     sopuli_rx_xa, _xb, _xc, _ga, _gb, _oa, _ob   p1, p3
--     sopuli_rx_wa, _wb, _wc                       p1, p2, p3
--
--   printf is a shell builtin, so the password in its arguments reaches no
--   process list; `docker exec` receives it on stdin only.
--
--   Section 6 leaves every account in place for those checks. Drop them after:
--   section 7's commented block does it.
--------------------------------------------------------------------------------

DEFINE tns        = //localhost:1521/FREEPDB1
DEFINE admin_user = system
DEFINE admin_pwd  = CHANGEME_ADMIN_PASSWORD

-- Known passwords, alphanumeric and 12 bytes for 07's reasons. Three distinct
-- ones, so a login result names WHICH password worked.
DEFINE p1         = Aq9xProbeOne
DEFINE p2         = Bq9xProbeTwo
DEFINE p3         = Cq9xProbeTri

SET LINESIZE 200
SET PAGESIZE 1000
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

COLUMN username        FORMAT A16
COLUMN account_status  FORMAT A32
COLUMN profile         FORMAT A20
COLUMN expiry_date     FORMAT A19

WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT ================================================================
PROMPT  sopuli-dba #529 probe v1: a password set on an EXPIRED account
PROMPT ================================================================
SELECT banner_full FROM v$version;
SELECT SYS_CONTEXT('USERENV','CON_NAME') AS container FROM dual;

--------------------------------------------------------------------------------
-- 0. Rollover gate, first: every question here is about a window, so on a
--    release without one there is nothing to measure. Raises rather than
--    substitutes, for 07's fifth trap.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 0. rollover capability ====
DECLARE
  l_n PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_n
    FROM dba_profiles WHERE profile = 'SOPULI_ROLLOVER' AND ROWNUM = 1;
  IF l_n = 0 THEN
    raise_application_error(-20001,
      'ABSENT: no SOPULI_ROLLOVER profile on this release, so no window to '
      || 'measure. Every section below is ABSENT rather than clean.');
  END IF;
  DBMS_OUTPUT.PUT_LINE('SOPULI_ROLLOVER present, continuing');
END;
/

--------------------------------------------------------------------------------
-- 1. Setup. Every account is dropped and recreated, and the grace profile is
--    the probe's own, for 08's reason. No password goes into this block, which
--    is why it may be PL/SQL.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 1. Setup ====
BEGIN
  FOR r IN (SELECT username FROM dba_users WHERE username LIKE 'SOPULI\_RX\_%' ESCAPE '\') LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || r.username || ' CASCADE';
    DBMS_OUTPUT.PUT_LINE('dropped a pre-existing ' || r.username);
  END LOOP;
  FOR r IN (SELECT DISTINCT profile FROM dba_profiles WHERE profile = 'SOPULI_PROBE_RX_GRACE') LOOP
    EXECUTE IMMEDIATE 'DROP PROFILE sopuli_probe_rx_grace';
    DBMS_OUTPUT.PUT_LINE('dropped a pre-existing SOPULI_PROBE_RX_GRACE');
  END LOOP;
END;
/
-- 08's grace profile: a one-second lifetime and a one-day grace.
CREATE PROFILE sopuli_probe_rx_grace LIMIT PASSWORD_LIFE_TIME 1/86400 PASSWORD_GRACE_TIME 1;

CREATE USER sopuli_rx_xa IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_xb IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_xc IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_wa IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_wb IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_wc IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_oa IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_ob IDENTIFIED BY "&p1" PROFILE sopuli_rollover;
CREATE USER sopuli_rx_ga IDENTIFIED BY "&p1" PROFILE sopuli_probe_rx_grace;
CREATE USER sopuli_rx_gb IDENTIFIED BY "&p1" PROFILE sopuli_probe_rx_grace;
GRANT CREATE SESSION TO sopuli_rx_xa, sopuli_rx_xb, sopuli_rx_xc,
  sopuli_rx_wa, sopuli_rx_wb, sopuli_rx_wc, sopuli_rx_oa, sopuli_rx_ob,
  sopuli_rx_ga, sopuli_rx_gb;
PROMPT baseline, every one must read plain OPEN -- a window is opened on purpose
PROMPT below, never inherited from CREATE USER (07 v1)
SELECT username, account_status, profile FROM dba_users
 WHERE username LIKE 'SOPULI\_RX\_%' ESCAPE '\' ORDER BY username;

--------------------------------------------------------------------------------
-- 2. The start states.
--
--    X: EXPIRED, by a bare PASSWORD EXPIRE with no window open.
--    W: EXPIRED and IN ROLLOVER -- IDENTIFIED BY p2 opens a window, then a bare
--       PASSWORD EXPIRE. 08's E7: p1 and p2 both answer ORA-28001 from here.
--    G: EXPIRED(GRACE) -- a login after the one-second lifetime, then a move to
--       the rollover profile. The move is itself a measurement: if it changes
--       the status, R7 and R8 start from whatever it left, and say so.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 2. start state X: EXPIRED ====
ALTER USER sopuli_rx_xa PASSWORD EXPIRE;
ALTER USER sopuli_rx_xb PASSWORD EXPIRE;
ALTER USER sopuli_rx_xc PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users
 WHERE username IN ('SOPULI_RX_XA','SOPULI_RX_XB','SOPULI_RX_XC') ORDER BY username;

PROMPT
PROMPT ==== 2. start state W: EXPIRED and IN ROLLOVER ====
ALTER USER sopuli_rx_wa IDENTIFIED BY "&p2";
ALTER USER sopuli_rx_wb IDENTIFIED BY "&p2";
ALTER USER sopuli_rx_wc IDENTIFIED BY "&p2";
PROMPT after IDENTIFIED BY p2, each must read OPEN and IN ROLLOVER:
SELECT username, account_status FROM dba_users
 WHERE username IN ('SOPULI_RX_WA','SOPULI_RX_WB','SOPULI_RX_WC') ORDER BY username;
ALTER USER sopuli_rx_wa PASSWORD EXPIRE;
ALTER USER sopuli_rx_wb PASSWORD EXPIRE;
ALTER USER sopuli_rx_wc PASSWORD EXPIRE;
PROMPT after the bare expiry, each must read EXPIRED and IN ROLLOVER:
SELECT username, account_status FROM dba_users
 WHERE username IN ('SOPULI_RX_WA','SOPULI_RX_WB','SOPULI_RX_WC') ORDER BY username;

PROMPT
PROMPT ==== 2. start state G: EXPIRED(GRACE), then the rollover profile ====
EXEC DBMS_SESSION.SLEEP(3)
WHENEVER SQLERROR CONTINUE NONE
CONNECT sopuli_rx_ga/"&p1"@&tns
SHOW USER
CONNECT sopuli_rx_gb/"&p1"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT after the grace-period logins, expecting EXPIRED(GRACE):
SELECT username, account_status, profile, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username IN ('SOPULI_RX_GA','SOPULI_RX_GB') ORDER BY username;
ALTER USER sopuli_rx_ga PROFILE sopuli_rollover;
ALTER USER sopuli_rx_gb PROFILE sopuli_rollover;
PROMPT after the move to SOPULI_ROLLOVER -- the status R7 and R8 start from:
SELECT username, account_status, profile, TO_CHAR(expiry_date,'YYYY-MM-DD HH24:MI:SS') AS expiry_date
  FROM dba_users WHERE username IN ('SOPULI_RX_GA','SOPULI_RX_GB') ORDER BY username;

--------------------------------------------------------------------------------
-- 3. Controls, from plain OPEN on the same profile. If C1 opens no window or C2
--    leaves p1 dead, the rows in section 4 cannot be read as a difference
--    between EXPIRED and OPEN.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 3. C1: from OPEN, IDENTIFIED BY p3 ====
ALTER USER sopuli_rx_oa IDENTIFIED BY "&p3";
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_OA';

PROMPT
PROMPT ==== 3. C2: from OPEN, IDENTIFIED BY p3 PASSWORD EXPIRE ====
ALTER USER sopuli_rx_ob IDENTIFIED BY "&p3" PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_OB';

--------------------------------------------------------------------------------
-- 4. The resets, each issued DIRECTLY -- 07's first trap, invariant 13.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 4. R1: from EXPIRED, IDENTIFIED BY p3 ====
ALTER USER sopuli_rx_xa IDENTIFIED BY "&p3";
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_XA';

PROMPT
PROMPT ==== 4. R2: from EXPIRED, IDENTIFIED BY p3 PASSWORD EXPIRE ====
ALTER USER sopuli_rx_xb IDENTIFIED BY "&p3" PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_XB';

PROMPT
PROMPT ==== 4. R3: from EXPIRED, R2 then EXPIRE PASSWORD ROLLOVER PERIOD ====
ALTER USER sopuli_rx_xc IDENTIFIED BY "&p3" PASSWORD EXPIRE;
PROMPT after the set:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_XC';
ALTER USER sopuli_rx_xc EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT after the close:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_XC';

PROMPT
PROMPT ==== 4. R4: from EXPIRED and IN ROLLOVER, IDENTIFIED BY p3 ====
ALTER USER sopuli_rx_wa IDENTIFIED BY "&p3";
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_WA';

PROMPT
PROMPT ==== 4. R5: from EXPIRED and IN ROLLOVER, IDENTIFIED BY p3 PASSWORD EXPIRE ====
ALTER USER sopuli_rx_wb IDENTIFIED BY "&p3" PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_WB';

PROMPT
PROMPT ==== 4. R6: from EXPIRED and IN ROLLOVER, R5 then the close ====
ALTER USER sopuli_rx_wc IDENTIFIED BY "&p3" PASSWORD EXPIRE;
PROMPT after the set:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_WC';
ALTER USER sopuli_rx_wc EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT after the close:
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_WC';

PROMPT
PROMPT ==== 4. R7: from section 2's G state, IDENTIFIED BY p3 ====
ALTER USER sopuli_rx_ga IDENTIFIED BY "&p3";
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_GA';

PROMPT
PROMPT ==== 4. R8: from section 2's G state, IDENTIFIED BY p3 PASSWORD EXPIRE ====
ALTER USER sopuli_rx_gb IDENTIFIED BY "&p3" PASSWORD EXPIRE;
SELECT username, account_status FROM dba_users WHERE username = 'SOPULI_RX_GB';

--------------------------------------------------------------------------------
-- 5. Nothing in this file reads SYS.USER$, so the status is the only evidence
--    the script itself gives. #504 showed the status can disagree with what
--    authenticates; the login checks in HOW TO RUN are the measurement, and
--    this section is only what they are compared against.
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- 6. Every account, as left for the login checks.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 6. every probe account, as left for the login checks ====
SELECT username, account_status, profile FROM dba_users
 WHERE username LIKE 'SOPULI\_RX\_%' ESCAPE '\' ORDER BY username;
PROMPT
PROMPT the accounts are LEFT IN PLACE. Run the login checks in HOW TO RUN, then
PROMPT section 7 below.

--------------------------------------------------------------------------------
-- 7. Cleanup, run separately after the login checks.
--
-- BEGIN
--   FOR r IN (SELECT username FROM dba_users WHERE username LIKE 'SOPULI\_RX\_%' ESCAPE '\') LOOP
--     EXECUTE IMMEDIATE 'DROP USER ' || r.username || ' CASCADE';
--   END LOOP;
--   EXECUTE IMMEDIATE 'DROP PROFILE sopuli_probe_rx_grace';
-- END;
-- /
--------------------------------------------------------------------------------
