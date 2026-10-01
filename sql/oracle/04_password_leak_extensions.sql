--------------------------------------------------------------------------------
-- sopuli-dba : password leakage probe, extensions   (v1)
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (FREEPDB1) and 21c XE 21.3.0.0.0
-- (XEPDB1) on 2026-09-11 (#407), and re-run on both after the review of #410
-- changed what §3 measures. Every finding below is from the later runs.
-- Run on 19c EE 19.3.0.0.0 (ORCLPDB1) on 2026-09-28 (#479), twice, with
-- AUDIT_TRAIL = DB,EXTENDED, AUDIT_SYS_OPERATIONS = TRUE and 01_audit_policy.sql
-- enabled first. It matches 21c: 6a is masked (`IDENTIFIED BY * REPLACE *`) and
-- attributed to SOPULITEST, and 6b is masked (`IDENTIFIED BY VALUES *`) in both
-- trails. Under trace, C8 alone reaches the trace directory, one file per run, and
-- the direct DDL is printed as `ALTER USER sopulitest IDE`. adump is populated (29
-- files, 594 ACTION lines) and holds no canary.
-- Run on 19c EE 19.32.0.0.0 (ORCLPDB1, an OCI Base Database Service DB system)
-- on 2026-10-01 (#581), twice, with AUDIT_TRAIL = DB,EXTENDED,
-- AUDIT_SYS_OPERATIONS = TRUE (as shipped), 01_audit_policy.sql, and AUDIT
-- USER / AUDIT ALTER USER BY ACCESS restored after 02's §8 had removed them --
-- the first run, without that, printed an empty traditional trail, which is
-- this file's own HOW TO RUN warning come true. sys_user was a throwaway common
-- user granted SYSDBA, not SYS, and SOPULITEST had its own profile (§0). 6a is
-- masked (`IDENTIFIED BY * REPLACE *`) and attributed to SOPULITEST in both
-- trails. 6b is masked (`IDENTIFIED BY VALUES *`) in the unified trail, and is
-- in NEITHER DBA_AUDIT_TRAIL NOR adump -- so its traditional half is absent,
-- not clean, and that differs from 19.3's "both trails". Cause not established:
-- the SYSDBA login not being SYS and the statement being recursive (EXECUTE
-- IMMEDIATE, which AUDIT_SYS_OPERATIONS does not cover) are both candidates.
-- Under trace, C8 alone reaches the trace directory, one file per run, and the
-- direct DDL is printed as `ALTER USER sopulitest IDE`, as on 19.3. adump is
-- populated (18221 ACTION lines) and holds no canary of this file's.
-- Untried on 18c, 11.2 and 12.x.
--
-- The three checks `02_password_leak_probe.sql` §6 and §7 described and left for
-- somebody to do by hand. Nobody did, for six weeks, which is the argument for
-- this file existing: a check that is a comment is a check that does not run.
--
--   6a  SELF-ROTATION   -- `ALTER USER … IDENTIFIED BY … REPLACE …`, the path
--                          where the account changes its own password and
--                          therefore exercises no ALTER USER privilege.
--                          Privilege auditing can miss what statement auditing
--                          catches, and the docs claim "rotations are audited".
--   6b  VERIFIER        -- `ALTER USER … IDENTIFIED BY VALUES '<verifier>'`.
--                          Oracle masks a *password*. Whether it masks a
--                          *verifier* is a separate question nobody had asked.
--   T   TRACE           -- the same rotations inside a 10046 level 12 traced
--                          session. sopuli never enables trace; a DBA who
--                          traces the session does, and §4 assumed the worst.
--
-- Canaries continue the main probe's numbering, so a hit in a shared directory
-- still says which path it came from:
--
--   C5  self-rotation, by the account itself
--   C6  ALTER USER issued directly, inside a traced session      <- sopuli's
--   C8  ALTER USER wrapped in a PL/SQL block, literal, traced    <- invariant 13
--   C9  ALTER USER wrapped, password assembled at runtime, traced
--
-- C6 against C8 is the pair that carries the argument, exactly as C2 against C3
-- does in the main probe. They differ only in the wrapper.
--
--
-- RESULTS
--   Identical on both versions, and the trace result is the one worth reading.
--
--   6a  SELF-ROTATION is captured and MASKED, including the old password:
--
--         ALTER USER sopulitest IDENTIFIED BY * REPLACE *
--
--       Attributed to SOPULITEST rather than to a service account, so the
--       privilege-auditing worry is answered: the event is recorded, by the
--       ACTIONS ALTER USER policy on both releases and by traditional
--       `AUDIT USER` on 21c as well. Both secrets are masked -- the REPLACE
--       clause carries the *current* password and is masked with the same `*`.
--
--   6b  THE VERIFIER IS MASKED TOO, in the trail and under trace alike:
--
--         ALTER USER sopulitest IDENTIFIED BY VALUES *
--
--       And the DDL truncates in a traced session exactly as the password form
--       does -- `len=44` declared, `ALTER USER sopulitest IDE` printed, cut at
--       the same character. No raw verifier (`S:` followed by 60 hex) appears
--       in any trace file or any OS audit file on either release.
--
--       **6b is issued under trace for this reason and it was not at first.**
--       The first version switched tracing off before §3, so "the verifier
--       appears in no trace file" was a claim about files that could not have
--       contained it -- clean because nothing was tracing. That is the `pop=n`
--       rule, committed by the script whose job is to apply it. Copilot caught
--       it on #410; the fix was to measure rather than to soften the claim.
--
--       One limit, stated because the result is otherwise easy to over-read:
--       §3 builds the DDL by concatenation, so the PL/SQL block's own text
--       never holds the verifier. A block with a verifier written into it as a
--       LITERAL would leak exactly as C8 does. The finding is about the DDL,
--       not about any way of reaching it -- invariant 13, one more time.
--
--       So the restore-from-verifier path, if one is ever added, does not
--       widen the audit exposure. It is still offline-crackable wherever the
--       verifier itself can be read, which is ADR-001's question and not this
--       one.
--
--   T   A TRACED SESSION DOES NOT CAPTURE THE PASSWORD, and this reverses the
--       assumption §4 carried. 10046 level 12, five traced sessions across the
--       two versions, every one identical:
--
--         PARSING IN CURSOR #… len=37 dep=0 uid=110 oct=43 lid=110 …
--         ALTER USER sopulitest IDE
--         END OF STMT
--
--       The statement is `ALTER USER sopulitest IDENTIFIED BY "<17 bytes>"`.
--       The trace prints 25 characters of it and stops at `IDE`, one character
--       into `IDENTIFIED`. Neither C6 nor C9 appears anywhere in any trace file.
--
--       C8 does, in full, because the traced statement there is the PL/SQL
--       block and the block's own text contains the password. Invariant 13
--       again, on a fifth surface: wrapping is what exposes it.
--
--       Note `len=37` beside 25 printed characters. Do not read the truncation
--       as a buffer limit that a longer account name would push past -- it is
--       keyed to the statement type, the same way the shared pool's absence of
--       a cursor is. A 30-byte password and a 128-byte one truncate at the same
--       place.
--
--   OS AUDIT FILES, with AUDIT_SYS_OPERATIONS = TRUE, differ by release and the
--   difference is not a leak but a surface:
--
--     21c    adump is populated -- 646 ACTION lines by the end of these runs
--            -- and the DDL appears masked there too:
--              ACTION :[37] 'ALTER USER sopulitest IDENTIFIED BY *'
--            Only the PL/SQL wrapper (C3, from the main probe) appears
--            verbatim, in one file.
--     26ai   adump holds 5 files, each a session header plus exactly one
--            ACTION line, and all five are the same internal call
--            (`dbms_cmp_int.drop_cmp_by_cmpid`). **No CREATE, ALTER or DROP
--            USER text reaches it at all**, and no file mentions SOPULITEST.
--            Traditional auditing is desupported on 23ai+, so
--            AUDIT_SYS_OPERATIONS is accepted and writes nothing useful. Read
--            that as the surface being ABSENT, not as a clean sweep of a
--            populated one -- it is the OS-file form of the `pop=n` rule.
--
--
-- HOW TO RUN
--   Needs `sopuli_svc` to exist already, holding CREATE SESSION and ALTER USER,
--   which is what `02_password_leak_probe.sql` position 1 also needs. Run that
--   first; this script assumes its account and reuses its canary prefix.
--
--     sqlplus -S /nolog @04_password_leak_extensions.sql "//host:1521/SERVICE"
--
--   Then run the greps §4 of this file prints, on the server.
--
--   **Run `02_password_leak_probe.sql` §2 again first, or re-enable auditing by
--   hand.** That script's §8 cleanup drops SOPULI_PROBE_POL and issues
--   `NOAUDIT USER`, so a run of this file straight afterwards records nothing
--   and reports a masking result it did not earn. That cost a run on each
--   version here before it was understood: on 21c the Oracle-supplied
--   ORA_SECURECONFIG policy is enabled and covers ALTER USER, so the trail
--   looked populated anyway; on 26ai nothing was enabled at all and the trail
--   came back empty. The second is the honest failure and the first is the
--   dangerous one.
--
-- THROWAWAY DATABASES ONLY. Creates SOPULITEST, plants four passwords in
-- cleartext across the audit trail and the trace directory, and leaves them.
--------------------------------------------------------------------------------

SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED
SET LINESIZE 200
SET PAGESIZE 1000
SET LONG 8000
SET TRIMSPOOL ON
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

-- Connection. `&1` is the easy-connect string, so the same file serves every
-- container in the stack without editing.
DEFINE tns      = &1
DEFINE sys_user = sys
DEFINE sys_pwd  = CHANGEME_SYS_PASSWORD
DEFINE svc_user = sopuli_svc
DEFINE svc_pwd  = CHANGEME_SVC_PASSWORD

-- Same prefix as the main probe, held apart from its suffix for the same
-- reason: every query below assembles the full string inside PL/SQL, so this
-- script's own SQL text can never match itself. §4's greps take the prefix
-- PLUS A DIGIT, never the bare prefix.
DEFINE cpfx = S0puliCanary
DEFINE c1   = S0puliCanary1Aq7x
DEFINE c5   = S0puliCanary5Eq7x
DEFINE c6   = S0puliCanary6Fq7x
DEFINE c8   = S0puliCanary8Hq7x

-- **EXIT mode stays on through setup and through every mutation**, and is
-- relaxed only around the release-specific reads that are *expected* to fail on
-- some releases. The main probe switches to CONTINUE straight after connecting,
-- which is right for it -- its §1 deliberately queries views that do not exist
-- everywhere. Copying that here would have made the §0 guard below decorative:
-- a missing service account, a failed CREATE USER or a failed rotation would
-- print an error and carry on to report a masking result nothing produced,
-- which is the exact failure this file's HOW TO RUN warns about.
WHENEVER SQLERROR EXIT FAILURE
CONNECT &sys_user/"&sys_pwd"@&tns AS SYSDBA
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

PROMPT
PROMPT ================================================================================
PROMPT  0. Setup
PROMPT ================================================================================

DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = UPPER('&svc_user');
  IF l_cnt = 0 THEN
    RAISE_APPLICATION_ERROR(-20001,
      '&svc_user does not exist. Run 02_password_leak_probe.sql position 1 '
      || 'first -- this script reuses its service account rather than making '
      || 'a second one that could differ from it.');
  END IF;
END;
/

-- Dropped rather than refused, unlike the main probe: that one plants the
-- canaries a whole release gate is read off and must not touch an account
-- somebody else made. This one runs after it, on the account it made.
--
-- ORA-01918 only. `WHEN OTHERS THEN NULL` here would swallow a drop that failed
-- for a real reason -- an active session, a locked account -- and the script
-- would then measure a PRE-EXISTING account while reporting a result, which is
-- the same class of mistake as reading an empty audit trail as a masked one.
DECLARE
BEGIN
  EXECUTE IMMEDIATE 'DROP USER sopulitest CASCADE';
  DBMS_OUTPUT.PUT_LINE('dropped the previous SOPULITEST');
EXCEPTION WHEN OTHERS THEN
  IF SQLCODE != -1918 THEN
    RAISE;
  END IF;
END;
/

-- Its own profile, verify function off and reuse unlimited. An OCI Base
-- Database DB system ships a DEFAULT enforcing ORA12C_STRONG_VERIFY_FUNCTION
-- (19.32.0.0.0, 2026-10-01, #581), and this file's canaries cannot satisfy it:
-- 6a's self-rotation hands the function the old password too, and it then
-- wants the new one to differ in 8 characters, which canaries sharing a
-- 12-character prefix never do. So the function-enabled case is measured by
-- 02_password_leak_probe.sql for the service-account path, and NOT for
-- self-rotation. On a DEFAULT without a function this changes nothing.
DECLARE
BEGIN
  EXECUTE IMMEDIATE 'DROP PROFILE sopuli_ext_prof';
EXCEPTION WHEN OTHERS THEN
  IF SQLCODE != -2380 THEN
    RAISE;
  END IF;
END;
/
CREATE PROFILE sopuli_ext_prof LIMIT PASSWORD_VERIFY_FUNCTION NULL
  PASSWORD_REUSE_MAX UNLIMITED PASSWORD_REUSE_TIME UNLIMITED
  FAILED_LOGIN_ATTEMPTS UNLIMITED;
CREATE USER sopulitest IDENTIFIED BY "&c1" PROFILE sopuli_ext_prof;
GRANT CREATE SESSION, ALTER SESSION TO sopulitest;
GRANT ALTER SESSION TO &svc_user;

-- Watermark, so a second run does not read the first one's rows. Read in
-- PL/SQL because 11.2 has no unified trail at all and a bare SELECT would
-- leave the substitution variable undefined -- the main probe's §3 has the
-- full account of what that costs.
SET TERMOUT OFF
VARIABLE ext_mark VARCHAR2(40)
BEGIN
  BEGIN
    EXECUTE IMMEDIATE
      'SELECT TO_CHAR(NVL(MAX(event_timestamp), TIMESTAMP ''1900-01-01 00:00:00''),'
      || ' ''YYYY-MM-DD HH24:MI:SS.FF6'') FROM unified_audit_trail'
      INTO :ext_mark;
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE != -942 THEN
        RAISE;
      END IF;
      :ext_mark := '1900-01-01 00:00:00.000000';
  END;
END;
/
COLUMN ext_mark NEW_VALUE uat_mark NOPRINT
SELECT :ext_mark AS ext_mark FROM dual;
SET TERMOUT ON

-- The traditional trail needs its own, and it is a DATE rather than a
-- TIMESTAMP. Absent on 23ai+, where the view itself is gone -- so this is read
-- with a handler for the same reason the unified one is, one release the other
-- way round.
SET TERMOUT OFF
VARIABLE ext_dat VARCHAR2(30)
BEGIN
  BEGIN
    EXECUTE IMMEDIATE
      'SELECT TO_CHAR(NVL(MAX(timestamp), DATE ''1900-01-01''),'
      || ' ''YYYY-MM-DD HH24:MI:SS'') FROM dba_audit_trail'
      INTO :ext_dat;
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLCODE != -942 THEN
        RAISE;
      END IF;
      :ext_dat := '1900-01-01 00:00:00';
  END;
END;
/
COLUMN ext_dat NEW_VALUE dat_mark NOPRINT
SELECT :ext_dat AS ext_dat FROM dual;
SET TERMOUT ON

PROMPT watermarks taken -- this run's rows only, in both trails

PROMPT
PROMPT --- WHICH policy is about to capture ALTER USER, and does one exist at all?
DECLARE
  l_out  VARCHAR2(4000);
  l_cov  PLS_INTEGER := 0;
  l_n    PLS_INTEGER;
BEGIN
  BEGIN
    -- Names the POLICIES THAT COVER ALTER USER, not merely the ones enabled.
    -- On 21c the Oracle-supplied ORA_SECURECONFIG covers it, so a run whose own
    -- policy had been dropped still produced masked rows -- and the result
    -- would have been credited to SOPULI_PROBE_POL. Listing coverage is what
    -- turns that from a silent mis-attribution into a line somebody reads.
    EXECUTE IMMEDIATE
      'SELECT LISTAGG(p.policy_name, '', '') WITHIN GROUP (ORDER BY p.policy_name),'
      || ' COUNT(*) FROM audit_unified_policies p'
      || ' JOIN audit_unified_enabled_policies e ON e.policy_name = p.policy_name'
      || ' WHERE p.audit_option = ''ALTER USER'''
      INTO l_out, l_cov;
    DBMS_OUTPUT.PUT_LINE('unified, covering ALTER USER   ' || NVL(l_out, '(none)'));
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('unified, covering ALTER USER   n/a on this release');
    l_cov := -1;
  END;

  BEGIN
    EXECUTE IMMEDIATE 'SELECT LISTAGG(audit_option, '', '') WITHIN GROUP '
                   || '(ORDER BY audit_option), COUNT(*) FROM dba_stmt_audit_opts '
                   || 'WHERE audit_option LIKE ''%USER%'''
      INTO l_out, l_n;
    DBMS_OUTPUT.PUT_LINE('traditional statement options  ' || NVL(l_out, '(none)'));
    IF l_cov < 1 THEN l_cov := l_n; END IF;
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('traditional statement options  n/a on this release');
  END;

  -- Refuse rather than report. A masking result read off an empty trail is
  -- worse than no result: it is the same shape as a real one.
  IF l_cov < 1 THEN
    RAISE_APPLICATION_ERROR(-20002,
      'nothing is auditing ALTER USER here, so every masking result below '
      || 'would be an EMPTY trail rather than a masked one. Re-run '
      || '02_password_leak_probe.sql §2 (or AUDIT POLICY / AUDIT USER by hand) '
      || 'and start again. 02''s §8 turns these off -- see HOW TO RUN.');
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 1. §6a — self-rotation
--
-- The account changes its own password. No ALTER USER privilege is exercised,
-- which is the whole reason this is a separate question: DBA_PRIV_AUDIT_OPTS
-- records statements executed *by virtue of* a privilege.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  1. Self-rotation -- the account changes its OWN password (C5)
PROMPT ================================================================================

-- EXIT mode held through the rotation. A self-rotation that failed -- wrong
-- password, a password-verify function, a release that spells REPLACE
-- differently -- would otherwise print `C5 planted` and leave §3 reporting an
-- absence as a masking result.
WHENEVER SQLERROR EXIT FAILURE
CONNECT sopulitest/"&c1"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

COLUMN whoami FORMAT A90
SELECT 'self-rotating as ' || SYS_CONTEXT('USERENV','SESSION_USER')
    || ', isdba=' || NVL(SYS_CONTEXT('USERENV','ISDBA'), '?') AS whoami
  FROM dual;

ALTER USER sopulitest IDENTIFIED BY "&c5" REPLACE "&c1";

PROMPT C5 planted. Note that REPLACE carries the CURRENT password too -- two
PROMPT secrets in one statement, and §3 below shows what happened to both.

--------------------------------------------------------------------------------
-- 2. Trace — the same rotations, in a traced session
--
-- level 12 is level 8 (waits) plus level 4 (binds), which is what a DBA
-- diagnosing a hang actually sets. Nothing here asks sopuli to enable trace;
-- the question is what happens when somebody else has.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  2. A traced session issues the rotations (10046 level 12)
PROMPT ================================================================================

-- And through trace setup and the three traced rotations, for the same reason:
-- a failed `ALTER SESSION SET events` followed by three successful rotations
-- produces a trace file that proves nothing and a PROMPT saying it does.
WHENEVER SQLERROR EXIT FAILURE
CONNECT &svc_user/"&svc_pwd"@&tns
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

ALTER SESSION SET tracefile_identifier = 'SOPULIPROBE';
ALTER SESSION SET events '10046 trace name context forever, level 12';

-- C6: exactly what sopuli sends, traced.
ALTER USER sopulitest IDENTIFIED BY "&c6";

DECLARE
  l_pwd VARCHAR2(30);
BEGIN
  -- C8: the complete secret is a literal in this block's own text.
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY "&c8"';

  -- C9: assembled at runtime, so the block text holds the halves and never the
  -- whole. A control, not a technique -- the main probe's §0 says why.
  l_pwd := '&cpfx' || '9Iq7x';
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY "' || l_pwd || '"';
END;
/

COLUMN tracefile FORMAT A110
SELECT value AS tracefile FROM v$diag_info WHERE name = 'Default Trace File';

PROMPT C6 (direct), C8 (wrapped literal) and C9 (assembled) planted under trace.
PROMPT Grep that file in §4. C6 absent and C8 present is the expected result.
PROMPT
PROMPT  **Trace is deliberately left ON here** and switched off at the end of §3,
PROMPT  so that 6b's IDENTIFIED BY VALUES is issued under it too. It was switched
PROMPT  off at this line in the first version, which made "the verifier appears in
PROMPT  no trace file" a claim about files that could not have contained it --
PROMPT  the grep was clean because nothing was tracing, which is the `pop=n` rule
PROMPT  again and this time the script was the one committing it.

--------------------------------------------------------------------------------
-- 3. §6b — IDENTIFIED BY VALUES, and what the trail shows for all of it
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  3. IDENTIFIED BY VALUES -- does Oracle mask a VERIFIER?
PROMPT ================================================================================

WHENEVER SQLERROR EXIT FAILURE
CONNECT &sys_user/"&sys_pwd"@&tns AS SYSDBA
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

-- Traced, so that §4's "the verifier is in no trace file" is a measurement
-- rather than a statement about an untraced session.
ALTER SESSION SET tracefile_identifier = 'SOPULIPROBE';
ALTER SESSION SET events '10046 trace name context forever, level 12';

PROMPT
PROMPT --- the verifier being re-applied
PROMPT  Masked to its first 24 characters. A verifier is offline-crackable, so
PROMPT  printing one in full puts it in this script's spool and in whatever
PROMPT  terminal scrollback the run lands in -- for a shape that 24 characters
PROMPT  already shows. What matters here is that `S:` and `T:` are present and
PROMPT  how long the whole string is, which is what §4's grep pattern is built
PROMPT  from; `sys.user$` is where to look if the full value is ever needed.
COLUMN spare4 FORMAT A70
SELECT SUBSTR(spare4, 1, 24) || '...[' || LENGTH(spare4) || ' chars]' AS spare4
  FROM sys.user$ WHERE name = 'SOPULITEST';

DECLARE
  l_v VARCHAR2(4000);
BEGIN
  SELECT spare4 INTO l_v FROM sys.user$ WHERE name = 'SOPULITEST';
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY VALUES ''' || l_v || '''';
  DBMS_OUTPUT.PUT_LINE('verifier re-applied under trace, length ' || LENGTH(l_v));
EXCEPTION WHEN OTHERS THEN
  -- SELECT ON SYS.USER$ is itself an open question (ADR-001). A release or an
  -- install that withholds it leaves 6b UNANSWERED rather than clean, and the
  -- distinction is this gate's whole reading discipline -- so it is said out
  -- loud rather than left as a missing row.
  DBMS_OUTPUT.PUT_LINE('6b UNANSWERED here -- ' || SUBSTR(SQLERRM, 1, 120));
END;
/

ALTER SESSION SET events '10046 trace name context off';

PROMPT
PROMPT --- unified trail, this run only. Every row should end in `*`.
COLUMN dbusername  FORMAT A14
COLUMN action_name FORMAT A12
COLUMN txt         FORMAT A60
SELECT TO_CHAR(event_timestamp, 'HH24:MI:SS.FF3') AS ts,
       dbusername, action_name, SUBSTR(sql_text, 1, 60) AS txt
  FROM unified_audit_trail
 WHERE object_name = 'SOPULITEST'
   AND event_timestamp > TO_TIMESTAMP('&uat_mark', 'YYYY-MM-DD HH24:MI:SS.FF6')
 ORDER BY event_timestamp;

PROMPT
PROMPT --- traditional trail, where the release still has one, this run only
PROMPT  Watermarked like the unified one above. Without it a re-run shows the
PROMPT  PREVIOUS run's rows mixed in, which is how the first run of this file
PROMPT  appeared to produce audit rows minutes before its own statements -- an
PROMPT  anomaly that cost real time to chase and was entirely the query's.
COLUMN username FORMAT A14
COLUMN sql_text FORMAT A60
SELECT TO_CHAR(timestamp, 'HH24:MI:SS') AS ts,
       username, action_name, SUBSTR(sql_text, 1, 60) AS sql_text
  FROM dba_audit_trail
 WHERE obj_name = 'SOPULITEST'
   AND timestamp > TO_DATE('&dat_mark', 'YYYY-MM-DD HH24:MI:SS')
 ORDER BY timestamp;

--------------------------------------------------------------------------------
-- 4. What SQL cannot reach
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  4. Off-database checks, run these on the server
PROMPT ================================================================================

SET HEADING OFF
SELECT '  grep -rlE ''&cpfx.[0-9]'' ' || value || '/     # trace: C8 only is the pass'
  FROM v$diag_info WHERE name = 'Diag Trace'
UNION ALL
SELECT '  grep -rlE ''&cpfx.[0-9]'' ' || value || '/     # OS audit files'
  FROM v$parameter WHERE name = 'audit_file_dest'
UNION ALL
SELECT '  grep -rhE ''^ACTION'' ' || value || '/ | wc -l     # is adump populated AT ALL?'
  FROM v$parameter WHERE name = 'audit_file_dest';
SET HEADING ON

PROMPT
PROMPT  Read the third one before the second. An `audit_file_dest` with no
PROMPT  ACTION lines is the OS-file form of the sweep's `pop=n`: a clean grep
PROMPT  there is an absence of evidence, not a masked statement. That is exactly
PROMPT  what 26ai gives -- traditional auditing is desupported on 23ai+, so
PROMPT  AUDIT_SYS_OPERATIONS is accepted and writes nothing.
PROMPT
PROMPT  The pattern is the prefix PLUS A DIGIT. The bare prefix appears in this
PROMPT  script's own text, so with AUDIT_SYS_OPERATIONS = TRUE it matches the
PROMPT  probe reading itself -- a false positive in the one place it would
PROMPT  matter most. The main probe's §7 has the full account.
PROMPT
PROMPT  Expected, on 26ai and 21c: the trace directory names the SOPULIPROBE
PROMPT  files and C8 is the only canary in them. C6 and C9 appear nowhere.
PROMPT

--------------------------------------------------------------------------------
-- 5. Cleanup
--
-- The account goes. The trace files and audit records stay -- they are the
-- evidence. What is actually in clear among them is narrower than it sounds,
-- and saying so precisely is the point of the whole file: the audit rows are
-- MASKED, and the one cleartext password is C8, in the SOPULIPROBE trace files,
-- because it is a literal inside a PL/SQL block. C6 and C9 are nowhere. Delete
-- them anyway once the findings are written up -- one is enough.
--------------------------------------------------------------------------------
PROMPT ================================================================================
PROMPT  5. Cleanup
PROMPT ================================================================================

DECLARE
BEGIN
  EXECUTE IMMEDIATE 'DROP USER sopulitest CASCADE';
  DBMS_OUTPUT.PUT_LINE('dropped SOPULITEST');
  EXECUTE IMMEDIATE 'DROP PROFILE sopuli_ext_prof';
  DBMS_OUTPUT.PUT_LINE('dropped SOPULI_EXT_PROF');
EXCEPTION WHEN OTHERS THEN
  DBMS_OUTPUT.PUT_LINE('drop failed -- ' || SQLERRM);
END;
/

PROMPT
PROMPT  Audit policies are LEFT ENABLED, unlike 02_password_leak_probe.sql §8.
PROMPT  That script turns them off, which is what made this one report an empty
PROMPT  trail when the two were run back to back. Turn them off by hand when the
PROMPT  whole gate is finished, not between its halves.
PROMPT
PROMPT  Then delete the SOPULIPROBE trace files and purge the planted audit
PROMPT  records -- 02_password_leak_probe.sql §8 has the DBMS_AUDIT_MGMT call
PROMPT  and the warning about never deleting from AUDSYS.AUD$UNIFIED by hand.
PROMPT
