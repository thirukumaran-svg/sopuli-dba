--------------------------------------------------------------------------------
-- sopuli-dba : lock, LCOUNT and rollover probe   (v3)
--
-- H4 (#455), the UC-2 reset's open behaviours. Answers what
-- use-cases/uc-02-personal-account-passwords.md sec.5 says has "not been run",
-- and what CLAUDE.md will not let be reasoned about instead:
--
--   Q1  does ALTER USER ... ACCOUNT UNLOCK on an account that is NOT locked
--       reset SYS.USER$.LCOUNT? (i.e. is "it does no harm" true?)
--   Q2  does ALTER USER ... IDENTIFIED BY reset LCOUNT on its own?
--   Q3  does ALTER USER ... IDENTIFIED BY clear LOCKED(TIMED)?
--   Q4  does ALTER USER ... IDENTIFIED BY clear an explicit ACCOUNT LOCK?
--   Q5  does the combined ACCOUNT UNLOCK + IDENTIFIED BY form parse, in either
--       clause order?
--   Q6  the UC-2 reset shape on a rollover profile: IDENTIFIED BY, then
--       EXPIRE PASSWORD ROLLOVER PERIOD back to back in one session. Which
--       passwords authenticate at each step?
--   Q7  EXTRA, and deliberately separate: the `expire-rollover` register entry
--       (docs/README.md) -- what IDENTIFIED BY ... PASSWORD EXPIRE does on a
--       profile with PASSWORD_ROLLOVER_TIME. This section MEASURES and decides
--       nothing; uc-02 sec.4.3 refuses that combination until someone reads it.
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (gvenzl/oracle-free:latest), FREEPDB1,
-- as SYSTEM, 2026-09-16, and on 21c XE 21.3.0.0.0 (gvenzl/oracle-xe:21-slim),
-- XEPDB1, as SYSTEM, 2026-09-26 (#461), twice -- results in RESULTS below. 18c,
-- 11.2 and 19c UNRUN. On a release with no rollover (18c, 11.2) section 7 reports ABSENT and
-- the script STOPS there; Q1-Q5 run on every line.
--
-- THROWAWAY DATABASES ONLY. Creates and drops an account, deliberately locks
-- it, and plants known passwords.
--
--
-- RESULTS -- 26ai Free 23.26.2.0.0, FREEPDB1, as SYSTEM, 2026-09-16
--
--   Q1  ACCOUNT UNLOCK on an UNLOCKED account RESETS LCOUNT: 2 -> 0.
--       So "it does no harm even if the account is not locked" is FALSE on this
--       release. It is silent and it leaves ACCOUNT_STATUS alone, but it clears
--       the failed-login counter that UC-1 sec.7's --lockout-margin reads.
--       tests/driver/test_oracle_unlock.py's docstring said the statement
--       "changes nothing" against an open account; it changes this.
--
--   Q2  IDENTIFIED BY does NOT reset LCOUNT: 2 -> 2.
--       The two statements differ on this axis, which is what makes Q1 matter
--       rather than being a curiosity.
--
--   Q3  IDENTIFIED BY does NOT clear LOCKED(TIMED). Status, LOCK_DATE and
--       LCOUNT are all unchanged (LOCKED(TIMED), 3), and a login with the NEW
--       password is ORA-28000. **A reset that does not unlock does not let the
--       person in.** This is the measurement H4's unlock question turns on.
--
--   Q4  IDENTIFIED BY does NOT clear a deliberate ACCOUNT LOCK either: status
--       stays LOCKED and the new password is ORA-28000. LOCKED and
--       LOCKED(TIMED) are distinct ACCOUNT_STATUS strings, so a plan can tell
--       a lock somebody chose from one a failed-login limit produced.
--
--   Q5  BOTH clause orders are ACCEPTED, measured on the DIRECT statement.
--       `ALTER USER ... ACCOUNT UNLOCK IDENTIFIED BY "..."` and
--       `ALTER USER ... IDENTIFIED BY "..." ACCOUNT UNLOCK` each leave the
--       account OPEN, and the password from the combined statement
--       authenticates. v2 got the same answer through EXECUTE IMMEDIATE, which
--       measured the PL/SQL parser rather than this -- same conclusion, but only
--       v3 measured the statement sopuli would actually send.
--
--       So the combined form parses. #455 still answered it the other way --
--       two statements -- because UC-1 sec.5 requires each attribute reported as
--       its own change, and because the combined shape is one no leak probe has
--       ever been run against.
--
--   Q6  The back-to-back reset works, and needs a CLOSED window to be read
--       honestly (see the v1 note below). From a baseline of plain OPEN:
--         step 1  IDENTIFIED BY p2    -> OPEN & IN ROLLOVER; BOTH p1 and p2
--                                        authenticate. UC-1 sec.6.3's window,
--                                        confirmed on the UC-2 statement.
--         step 2  EXPIRE PASSWORD ROLLOVER PERIOD, same session, no verification
--                                     -> OPEN; p1 ORA-01017, p2 authenticates.
--         step 3  the same statement with no window open -> ACCEPTED, silently,
--                 status still OPEN. Matches what `finish_rollover`'s docstring
--                 and UC-1 sec.6.3 already record.
--
--   Q6b The full shape on a locked account -- ACCOUNT UNLOCK, then IDENTIFIED BY,
--       then EXPIRE PASSWORD ROLLOVER PERIOD -- leaves OPEN, the new password
--       working with nothing else needed, and the superseded one ORA-01017.
--       Three statements, in UC-1 sec.5's order.
--
--   Q7  EXTRA, and it is the one that changes a document. Measured on the DIRECT
--       statement in v3; v2's answer came from a PL/SQL-wrapped impostor and
--       could not have supported a claim about the seen path's real DDL.
--
--       On a rollover profile `ALTER USER ... IDENTIFIED BY "..." PASSWORD
--       EXPIRE` is ACCEPTED, and the resulting status is `EXPIRED & IN ROLLOVER`
--       -- both states at once.
--
--       **Expiring does NOT end the old password's window.** Both login checks
--       run as separate invocations with the CONNECT on stdin: the OLD password
--       answers ORA-28001 and so does the NEW one. ORA-28001 means the password
--       AUTHENTICATED and is merely expired -- so during the window the old
--       password is still live, and is itself a way to set the new one. Both are
--       live, both expired.
--
--       This measured the `expire-rollover` register entry on 26ai. 21c, below,
--       is the second release it needed. Recorded here, decided nowhere.
--
--
-- RESULTS -- 21c XE 21.3.0.0.0, XEPDB1, as SYSTEM, 2026-09-26 (#461)
--
--   Two full runs, each followed by the two Q7 login checks. The second run's
--   statuses, LCOUNTs and login results were diffed against the first's with the
--   timestamps stripped: identical.
--
--   Q1-Q6b  identical to 26ai, line for line. ACCOUNT UNLOCK on an unlocked
--           account resets LCOUNT 2 -> 0; IDENTIFIED BY leaves it at 2; neither
--           LOCKED(TIMED) nor LOCKED is cleared by IDENTIFIED BY (ORA-28000 with
--           the new password); both combined clause orders are accepted; Q6's
--           window opens with both passwords live, closes to p1 ORA-01017, and
--           the close with no window open is accepted silently; Q6b ends OPEN,
--           p3 working and p2 ORA-01017.
--
--   Q7      identical to 26ai. `IDENTIFIED BY ... PASSWORD EXPIRE` is ACCEPTED on
--           SOPULI_ROLLOVER, the status is `EXPIRED & IN ROLLOVER`, and the OLD
--           password p1 answers ORA-28001, as does the new p2. Expiring does not
--           end the window on 21c either. With 26ai, that settles the register
--           entry: the two releases it named agree.
--
--
-- HOW TO RUN
--   **Do not substitute the password with a command-line tool.** `sed 's/.../pw/'`
--   puts the secret in argv, where `ps` and the Windows process list can read it,
--   which is invariant 1 and is exactly what the CONNECTs below are written to
--   avoid. v2 of this file documented a `sed` one-liner and was wrong to.
--
--   Copy the file, edit the DEFINE in the copy, run the copy, delete it -- which
--   is what 02_password_leak_probe.sql sec.0 already prescribes:
--
--     cp 07_lock_and_rollover_probe.sql /tmp/probe.sql
--     $EDITOR /tmp/probe.sql                     # set admin_pwd
--     MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 \
--       sqlplus -S /nolog < /tmp/probe.sql
--     rm /tmp/probe.sql
--
--   Piped rather than mounted because the compose stack mounts oracle-init/ and
--   nothing else. MSYS_NO_PATHCONV is a Git Bash detail: without it `/nolog` is
--   rewritten to a Windows path and sqlplus prints its usage instead of running.
--
--   admin_user needs ALTER USER, CREATE USER, DROP USER, SELECT ON DBA_USERS and
--   -- for the LCOUNT half -- SELECT ON SYS.USER$, which
--   test/oracle-init/01_test_profiles.sql sec.5 grants to SYSTEM CONTAINER=ALL.
--   Without it Q1 and Q2 cannot be answered at all and section 0 says so rather
--   than reporting a zero it could not read.
--
--
-- FOUR TRAPS, ALL FOUR HIT BY AN EARLIER VERSION OF THIS FILE
--   - **Never wrap password DDL in a PL/SQL block, not even in a probe.**
--     v2 measured Q5 and Q7 with `EXECUTE IMMEDIATE 'ALTER USER ... IDENTIFIED
--     BY "&p"'`, which is invariant 13 -- and this repository has MEASURED that
--     the wrapper is the one thing that retains the password verbatim in V$SQL
--     (02_password_leak_probe.sql, canary C3). So the probe was planting the
--     leak it exists to reason about, and worse, it was measuring the WRAPPED
--     statement while the document claimed a result about the DIRECT one. Every
--     password-bearing statement below is issued directly. The two remaining
--     blocks (section 0's privilege check, section 1's DROP USER) carry no
--     secret, which is the whole distinction.
--   - **A PROMPT line must not end in a hyphen.** Trailing `-` is SQL*Plus's
--     continuation character, so `PROMPT -- 6. Q5 ------` silently ate the
--     `BEGIN` on the next line and v1's Q5 did not run at all -- it reported
--     nothing rather than failing. Every banner here ends in a word.
--   - **CONNECT resets SERVEROUTPUT.** Every DBMS_OUTPUT verdict after the first
--     connect printed nothing in v1. `SET SERVEROUTPUT ON` follows every CONNECT.
--   - **An expired-password login makes sqlplus PROMPT for a new one**, and the
--     prompt reads the SCRIPT as its answer -- v1 and v2 both consumed their own
--     following lines and reported ORA-00988. No section here attempts a login
--     against an expired account; section 9 documents it as a separate
--     invocation whose stdin ends immediately after the CONNECT.
--
-- WHENEVER SQLERROR is EXIT FAILURE by default in this script, and is relaxed to
-- CONTINUE NONE only around operations that are MEANT to fail -- the wrong-
-- password logins, the two combined-DDL trials, and the no-window re-issue. v2
-- left CONTINUE active throughout, so a failed grant or a missing profile would
-- have sailed on and produced normal-looking results for the wrong reason.
--------------------------------------------------------------------------------

DEFINE tns        = //localhost:1521/FREEPDB1
DEFINE admin_user = system
DEFINE admin_pwd  = CHANGEME_ADMIN_PASSWORD

-- The probe account. Dropped and recreated on every run.
DEFINE acct       = sopuli_h4_user

-- Known passwords, one per step, so a login result names WHICH password worked.
-- Alphanumeric and 12 bytes: inside 11.2's 30-byte limit and the alnum_safe
-- charset, so no quoting or verify-function question is mixed into this test.
DEFINE p1         = Aq7xProbeOne
DEFINE p2         = Bq7xProbeTwo
DEFINE p3         = Cq7xProbeSix
DEFINE p4         = Dq7xProbeFor
DEFINE pwrong     = Zq9xNotThePw

SET LINESIZE 200
SET PAGESIZE 1000
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

COLUMN username        FORMAT A16
COLUMN account_status  FORMAT A22
COLUMN lcount          FORMAT A6
COLUMN lock_date       FORMAT A19
COLUMN profile         FORMAT A16

WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT ================================================================
PROMPT  sopuli-dba H4 probe v3: lock, LCOUNT and rollover
PROMPT ================================================================
SELECT banner_full FROM v$version;
SELECT SYS_CONTEXT('USERENV','CON_NAME') AS container FROM dual;

--------------------------------------------------------------------------------
-- 0. Can we read LCOUNT at all?
--
-- Its own line, because a probe reporting "LCOUNT 0" when what happened was
-- ORA-01031 would answer Q1 backwards. 02-oracle-privileges.md sec.4 makes the
-- same distinction for check 3: could-not-read is a third answer.
--
-- A PL/SQL block with a handler, because the question IS whether the statement
-- raises. No password goes anywhere near it, which is why the invariant-13 rule
-- above does not reach this one.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 0. LCOUNT readability ====
DECLARE
  l_n PLS_INTEGER;
BEGIN
  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM sys.user$ WHERE ROWNUM = 1' INTO l_n;
  DBMS_OUTPUT.PUT_LINE('SYS.USER$ readable: YES, so Q1 and Q2 are answerable');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('SYS.USER$ NOT readable (' || SQLERRM || ')');
    DBMS_OUTPUT.PUT_LINE('*** Q1 and Q2 are UNANSWERABLE on this run ***');
END;
/

--------------------------------------------------------------------------------
-- 1. A fresh account on the lockout profile.
--
-- SOPULI_LOCKOUT is FAILED_LOGIN_ATTEMPTS 3, PASSWORD_LOCK_TIME 1/1440 (one
-- minute) -- test/oracle-init/01_test_profiles.sql sec.1. Two failed logins
-- therefore leave the account OPEN with LCOUNT 2, which is the state Q1 needs.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 1. Setup ====
BEGIN
  EXECUTE IMMEDIATE 'DROP USER &acct CASCADE';
  DBMS_OUTPUT.PUT_LINE('dropped a pre-existing &acct');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('no pre-existing &acct to drop');
END;
/
CREATE USER &acct IDENTIFIED BY "&p1" PROFILE sopuli_lockout;
GRANT CREATE SESSION TO &acct;
PROMPT created &acct on SOPULI_LOCKOUT with p1

PROMPT a baseline login, so LCOUNT starts from a known zero and p1 is proven good
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 2. Q1 -- does ACCOUNT UNLOCK reset LCOUNT on an account that is not locked?
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 2. Q1: ACCOUNT UNLOCK on an UNLOCKED account ====
PROMPT two failed logins (the limit is 3, so the account stays OPEN)
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT before ACCOUNT UNLOCK:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct ACCOUNT UNLOCK;
PROMPT issued ALTER USER ... ACCOUNT UNLOCK against an account that was NOT locked

PROMPT after ACCOUNT UNLOCK:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

--------------------------------------------------------------------------------
-- 3. Q2 -- does IDENTIFIED BY reset LCOUNT on its own?
--
-- The question that decides whether Q1 matters. If setting a password already
-- zeroed the counter, adding ACCOUNT UNLOCK would cost nothing on this axis.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 3. Q2: IDENTIFIED BY and LCOUNT ====
PROMPT two more failed logins
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT before IDENTIFIED BY:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct IDENTIFIED BY "&p2";
PROMPT issued ALTER USER ... IDENTIFIED BY p2

PROMPT after IDENTIFIED BY:
SELECT u.username, u.account_status,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

--------------------------------------------------------------------------------
-- 4. Q3 -- does IDENTIFIED BY clear LOCKED(TIMED)?
--
-- uc-02 sec.5: "Whether setting a password affects the timer has not been run,
-- and nothing here assumes it does." This is that run.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 4. Q3: IDENTIFIED BY against LOCKED(TIMED) ====
PROMPT three failed logins, which reaches FAILED_LOGIN_ATTEMPTS 3
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
CONNECT &acct/"&pwrong"@&tns
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT after the third failure, expecting LOCKED(TIMED):
SELECT u.username, u.account_status,
       TO_CHAR(u.lock_date,'YYYY-MM-DD HH24:MI:SS') AS lock_date,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct IDENTIFIED BY "&p3";
PROMPT issued ALTER USER ... IDENTIFIED BY p3, with no ACCOUNT UNLOCK

PROMPT after IDENTIFIED BY, is the timed lock still there?
SELECT u.username, u.account_status,
       TO_CHAR(u.lock_date,'YYYY-MM-DD HH24:MI:SS') AS lock_date,
       (SELECT TO_CHAR(s.lcount) FROM sys.user$ s WHERE s.name = u.username) AS lcount
  FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT can the owner log in with the NEW password while the timed lock stands?
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&p3"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 5. Q4 -- does IDENTIFIED BY clear a DELIBERATE lock?
--
-- The distinction H4's unlock answer rests on: LOCKED(TIMED) is a lock nobody
-- chose, LOCKED is one a DBA issued. errors.py's ORA-28000 hint already tells an
-- operator ACCOUNT_STATUS tells them apart; this checks the statuses really are
-- distinct strings, and that a reset does not quietly clear the deliberate one.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 5. Q4: IDENTIFIED BY against a deliberate ACCOUNT LOCK ====
ALTER USER &acct ACCOUNT UNLOCK;
ALTER USER &acct ACCOUNT LOCK;
PROMPT issued ALTER USER ... ACCOUNT LOCK, the deliberate kind
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

ALTER USER &acct IDENTIFIED BY "&p4";
PROMPT issued ALTER USER ... IDENTIFIED BY p4

PROMPT after IDENTIFIED BY, is the deliberate lock still there?
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT can the owner log in? ORA-28000 means the lock survived
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&p4"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 6. Q5 -- does the combined form parse, in either clause order?
--
-- The instinct in #455 was that one statement doing both "does no harm".
-- Whether it PARSES is the first half of that; whether it is the right shape is
-- a design question this script does not touch. Both orders are tried, because
-- Oracle's alter_user grammar is order-sensitive in places.
--
-- **Issued DIRECTLY, which is the whole point of v3.** v2 wrapped these in
-- EXECUTE IMMEDIATE, so it measured how the PL/SQL engine parses the statement
-- rather than how the server parses the one sopuli would send -- and it retained
-- the password in the block text while doing it. An ORA- error printed under one
-- of these IS the result; silence means ACCEPTED.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 6. Q5: the combined statement, issued directly ====
WHENEVER SQLERROR CONTINUE NONE

PROMPT clause order 1: ACCOUNT UNLOCK before IDENTIFIED BY
ALTER USER &acct ACCOUNT UNLOCK IDENTIFIED BY "&p1";
PROMPT no ORA- above means ACCEPTED
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

WHENEVER SQLERROR EXIT FAILURE
ALTER USER &acct ACCOUNT LOCK;
WHENEVER SQLERROR CONTINUE NONE

PROMPT clause order 2: IDENTIFIED BY before ACCOUNT UNLOCK
ALTER USER &acct IDENTIFIED BY "&p2" ACCOUNT UNLOCK;
PROMPT no ORA- above means ACCEPTED
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the password from the combined statement actually work?
CONNECT &acct/"&p2"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 7. Q6 -- the UC-2 reset shape on a rollover profile.
--
-- SOPULI_ROLLOVER is PASSWORD_ROLLOVER_TIME 1/24. UC-1 sec.6.3 has the window
-- behaviour measured; what is new is the back-to-back sequence a UC-2 reset
-- issues -- set, then close -- in one session, with no verification between.
--
-- **The capability is DETECTED, not assumed.** 18c and 11.2 have no gradual
-- password rollover, so test/oracle-init/01_test_profiles.sql does not create
-- SOPULI_ROLLOVER there. v2 simply issued the profile change and carried on when
-- it failed, which would have produced ordinary-looking Q6 and Q7 results
-- measured against the LOCKOUT profile -- a clean-looking answer to a question
-- nobody asked. If the profile is absent this reports ABSENT and stops.
--
-- **The baseline must also start with the window CLOSED**, which v1 got wrong:
-- moving the account onto the rollover profile and setting p1 opens a window of
-- its own, so v1's "old password" was the one from before p1, and p1 failing
-- during the window looked like a finding when it was the setup.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 7. Q6: reset on a rollover profile ====
-- **A fifth trap, and v3's own.** The first attempt at this gate used the
-- `COLUMN ... NEW_VALUE` idiom to compute either `EXIT` or a no-op and then run
-- it as `&rollover_action`. On 26ai it printed `SP2-0734: unknown command
-- beginning "&rollover_..."` and CARRIED ON -- the substitution never happened
-- and the guard **failed open**, which is the one direction a guard must never
-- fail. It was invisible on this release because the profile exists here; on 18c
-- it would have done precisely what the gate exists to prevent.
--
-- So the check raises instead. Under the script's default WHENEVER SQLERROR EXIT
-- FAILURE this stops the run and prints the reason, and there is no substitution
-- step between deciding and acting.
DECLARE
  l_n PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_n
    FROM dba_profiles WHERE profile = 'SOPULI_ROLLOVER' AND ROWNUM = 1;
  IF l_n = 0 THEN
    raise_application_error(-20001,
      'ABSENT: no SOPULI_ROLLOVER profile on this release. Sections 7-9 are '
      || 'ABSENT rather than clean, and Q1-Q5 above still stand.');
  END IF;
  DBMS_OUTPUT.PUT_LINE('SOPULI_ROLLOVER present, continuing into Q6');
END;
/

ALTER USER &acct ACCOUNT UNLOCK;
ALTER USER &acct PROFILE sopuli_rollover;
ALTER USER &acct IDENTIFIED BY "&p1";
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT baseline: profile SOPULI_ROLLOVER, password p1, window deliberately CLOSED
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');
PROMPT the status above must read plain OPEN. Anything else invalidates step 1
PROMPT and p1 must authenticate right now:
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT step 1: ALTER USER ... IDENTIFIED BY p2, which OPENS the window
ALTER USER &acct IDENTIFIED BY "&p2";
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the OLD password p1 still authenticate during the window?
CONNECT &acct/"&p1"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT does the NEW password p2 authenticate during the window?
CONNECT &acct/"&p2"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT step 2: ALTER USER ... EXPIRE PASSWORD ROLLOVER PERIOD, same session
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT does the OLD password p1 still authenticate after the close?
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&p1"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT does the NEW password p2 still authenticate after the close?
CONNECT &acct/"&p2"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

PROMPT
PROMPT step 3: the same statement again, with NO window open
WHENEVER SQLERROR CONTINUE NONE
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT no ORA- above means ACCEPTED with no window open
WHENEVER SQLERROR EXIT FAILURE
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

--------------------------------------------------------------------------------
-- 8. Q6b -- unlock, reset, close: the full UC-2 shape on a locked account.
--
-- Three statements in the order UC-1 sec.5 already uses (unlock first, after the
-- guardrails). This is what a UC-2 reset would issue if H4 answers "unlock by
-- default" and "close the window by default".
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 8. Q6b: unlock, reset, close on a locked account ====
ALTER USER &acct ACCOUNT LOCK;
PROMPT locked deliberately, and left on the rollover profile:
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');
ALTER USER &acct ACCOUNT UNLOCK;
ALTER USER &acct IDENTIFIED BY "&p3";
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT issued all three, in that order
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');
PROMPT can the owner log in with p3, with nothing else needed?
CONNECT &acct/"&p3"@&tns
SHOW USER
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED
PROMPT and is the superseded p2 dead?
WHENEVER SQLERROR CONTINUE NONE
CONNECT &acct/"&p2"@&tns
SHOW USER
WHENEVER SQLERROR EXIT FAILURE
CONNECT &admin_user/"&admin_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED

--------------------------------------------------------------------------------
-- 9. Q7 -- EXTRA: the `expire-rollover` register entry.
--
-- NOT part of H4's decision. docs/README.md carries this as an unverified entry
-- and uc-02 sec.4.3 refuses a SEEN reset on a rollover profile until it is
-- settled. This section measures; whether the refusal lifts is a decision on
-- #438/#457, not something this script or #455 may settle.
--
-- Issued DIRECTLY, for section 6's reason: this is the statement the seen path
-- would send, and v2 measured a PL/SQL-wrapped impostor of it.
--
-- **No login is attempted here.** After this the account is EXPIRED, and an
-- expired-password CONNECT prompts for a replacement and eats the rest of the
-- script. Run each check as its own invocation, with the CONNECT on stdin --
-- never as a sqlplus command-line argument, which would put the credential in
-- `ps`. The blank lines answer the password-change prompt so it fails cleanly
-- with ORA-00988 instead of hanging:
--
--   printf 'CONNECT %s/"%s"@%s\n\n\n' <acct> <OLD pw, p1> //localhost:1521/FREEPDB1 \
--     | MSYS_NO_PATHCONV=1 docker exec -i sopuli-test-oracle-free-1 sqlplus -S /nolog
--
--   ...and again with the NEW password (p2). ORA-28001 on either one means that
--   password AUTHENTICATED and is merely expired; ORA-01017 means it is dead.
--   The old password is the interesting one: it says whether PASSWORD EXPIRE
--   ended the rollover window or left it open.
--------------------------------------------------------------------------------
PROMPT
PROMPT ==== 9. Q7 EXTRA: IDENTIFIED BY ... PASSWORD EXPIRE on a rollover profile ====
ALTER USER &acct IDENTIFIED BY "&p1";
ALTER USER &acct EXPIRE PASSWORD ROLLOVER PERIOD;
PROMPT baseline restored to p1, window closed:
SELECT u.username, u.account_status FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT
PROMPT is the suffixed statement ACCEPTED on a rollover profile? (issued directly)
WHENEVER SQLERROR CONTINUE NONE
ALTER USER &acct IDENTIFIED BY "&p2" PASSWORD EXPIRE;
PROMPT no ORA- above means ACCEPTED
WHENEVER SQLERROR EXIT FAILURE
PROMPT resulting status: EXPIRED, IN ROLLOVER, or both?
SELECT u.username, u.account_status, u.profile FROM dba_users u WHERE u.username = UPPER('&acct');

PROMPT
PROMPT the account is LEFT IN PLACE for the two separate login checks above.
PROMPT Drop it afterwards with: DROP USER &acct CASCADE;
PROMPT
PROMPT ================================================================
PROMPT  A login line reading USER is "" means that CONNECT FAILED.
PROMPT  The ORA- code is printed immediately above it.
PROMPT ================================================================
