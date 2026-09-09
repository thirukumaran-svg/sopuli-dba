--------------------------------------------------------------------------------
-- sopuli-dba : password leakage probe   (v3)
--
-- Release gate 2 (docs/design/04-testing.md §6). Answers the question that
-- docs/decisions/adr-001-privilege-model.md and docs/design/02-oracle-privileges.md §4
-- both refuse to answer from reasoning: does the password text of
--
--     ALTER USER "SOPULITEST" IDENTIFIED BY "<secret>"
--
-- survive anywhere queryable, on this version, on this database?
--
-- Passwords cannot be bind variables. DDL is literal text. So the secret is on
-- the wire and in the parser on every rotation, and the only open question is
-- what Oracle retains afterwards.
--
-- THROWAWAY DATABASES ONLY. Creates a user, enables auditing, leaves audit
-- records containing deliberately-planted secrets.
--
--
-- RESULTS SO FAR
--   26ai Free 23.26.2.0.0, CDB$ROOT and FREEPDB1, both as SYS:
--     - unified audit records the statement as "IDENTIFIED BY *", at write time.
--       Masked in AUDSYS.AUD$UNIFIED as well as in UNIFIED_AUDIT_TRAIL.
--     - V$SQL holds no cursor for the DDL at all. Not masked, absent. Client
--       -issued CREATE/ALTER USER and EXECUTE IMMEDIATE'd DDL alike.
--     - the one leak is an anonymous PL/SQL block whose own text contains the
--       password as a literal (C3), visible in V$SQL* and V$DB_OBJECT_CACHE.
--       Oracle's protection is keyed to the CREATE/ALTER USER statement; a
--       block that merely contains one is an ordinary block.
--     - CDB$ROOT and PDB results identical.
--
--   2026-08-26, 26ai Free 23.26.2.0.0, all three HOW TO RUN positions. The
--   SYS-only caveat above is now RESOLVED: two of the three ran with
--   isdba=FALSE, so the capture is attributable to SOPULI_PROBE_POL rather than
--   to mandatory SYSDBA auditing.
--
--     position                              isdba   audited   leaked
--     1  FREEPDB1, svc = SOPULI_SVC         FALSE   4 of 4    C3 only
--     2  FREEPDB1, svc = SYS AS SYSDBA      TRUE    4 of 4    C3 only
--     3  CDB$ROOT, svc = C##SOPULI_SVC      FALSE   4 of 4    C3 only
--
--   Identical in all three. C1 (client CREATE USER), C2 (client ALTER USER --
--   the statement sopuli actually issues) and C4 (EXECUTE IMMEDIATE with the
--   password assembled at runtime) are clean in every source probed. The only
--   leak is C3, in V$SQL / V$SQLAREA / V$SQLSTATS / GV$SQL (sql_text and
--   sql_fulltext) and V$DB_OBJECT_CACHE.name.
--
--   So invariant 13 is measured rather than assumed, and it is measured the
--   right way round: wrapping the DDL is what exposes the password, and issuing
--   it directly is what hides it. C2 and C3 differ only in the wrapper.
--
--   2026-09-08, 21c XE 21.3.0.0.0 (gvenzl/oracle-xe:21-slim), XEPDB1, position
--   1 -- svc_user = SOPULI_SVC, isdba=FALSE (#380). **Identical to 26ai**, and
--   it adds the half 26ai cannot answer at all:
--
--     UNIFIED_AUDIT_TRAIL   events=4  with sql_text=4   clean
--     DBA_AUDIT_TRAIL       events=3  with sql_text=3   clean
--     SYS.AUD$.sqltext                                  clean
--     DBA_COMMON_AUDIT_TRAIL.sql_text                   clean
--     leaks: C3 only, in V$SQL / V$SQLAREA / V$SQLSTATS / GV$SQL and
--            V$DB_OBJECT_CACHE.name
--
--   **Traditional auditing masks the password too.** 26ai desupported it, so
--   this could not be measured there, and 11.2 to 21c is where it is the only
--   audit trail many sites have. C1, C2 and C4 clean in every source.
--
--   Section 7's off-database greps have now been RUN, for the first time, on
--   21c with AUDIT_SYS_OPERATIONS = TRUE: no numbered canary appears in
--   audit_file_dest, the trace directory, the listener log or the client
--   history. That answers 02-oracle-privileges.md §4's "OS audit files --
--   untested, assume not redacted" on 21c. It stays open on 11.2, which is the
--   version the row says it matters most on.
--
--   2026-09-08, 18c XE 18.4.0.0.0 (gvenzl/oracle-xe:18-slim), XEPDB1, position
--   1, isdba=FALSE (#381). **Identical again** -- 4 unified events and 3
--   traditional, all with sql_text, every audit source clean, C3 the only leak,
--   and no numbered canary anywhere under audit_file_dest, the trace directory
--   or the listener log.
--
--   So invariant 13 now holds on three releases and two audit implementations,
--   and the C3-only result has not varied once.
--
--   2026-09-08, 11g XE 11.2.0.2.0 (gvenzl/oracle-xe:11.2.0.2-slim), non-CDB,
--   position 1, isdba=FALSE (#382). **NOT identical, and this is the one to
--   read.** Traditional auditing is clean as on 18c and 21c -- DBA_AUDIT_TRAIL
--   3 of 3 with sql_text, SYS.AUD$ and DBA_COMMON_AUDIT_TRAIL clean -- and the
--   off-database greps are clean across 835 adump files, which answers
--   02-oracle-privileges.md §4's "OS audit files, untested, matters most on
--   11.2" outright.
--
--   But V$SQLSTATS leaks **C2 and C4** as well as C3:
--
--     V$SQLSTATS.sql_text        *** LEAK ***  C2(1) C3(2) C4(1)
--     V$SQLSTATS.sql_fulltext    *** LEAK ***  C2(1) C3(2) C4(1)
--     V$SQL.sql_text             *** LEAK ***  C3(1)      <- as everywhere else
--
--   C2 is the statement sopuli issues: a plain client-side ALTER USER, no
--   wrapper. Confirmed by reading the view directly rather than trusting the
--   sweep -- `ALTER USER sopulitest IDENTIFIED BY "<canary>"` is there verbatim.
--   V$SQL holds no cursor for it on 11.2 either, exactly as on every other
--   release; V$SQLSTATS keeps its own copy, and that copy outlives the cursor.
--
--   So the *conclusion* "issuing the DDL directly keeps the password out of the
--   shared pool" holds on 18c, 21c and 26ai and NOT on 11.2. Invariant 13's
--   reasoning is untouched -- C3 is worse everywhere. The service account cannot
--   read V$SQLSTATS (ORA-00942, measured); a dictionary reader can.
--
--   DECIDED in #387, 2026-09-09: the tool documents this and does not warn or
--   refuse. 02-oracle-privileges.md sec.8 P8 has the decision and the two
--   declined alternatives; sec.4 has the table; docs/security-model.md sec.5 is
--   what an operator on 11.2 is told. Do not quote a leak result from 11.2
--   without reading that row.
--
--   2026-09-09, same image, RETENTION -- the two questions #387 had to answer
--   before it could be decided. Neither is part of the sweep above; both were
--   run by hand and are written out here so they can be repeated on 12.x and
--   19c, which is where the boundary below 18c is still unmeasured.
--
--     method: as SYS, create SOPULI_SVC with CREATE SESSION + ALTER USER only;
--             as SOPULI_SVC issue `ALTER USER sopulitest IDENTIFIED BY
--             "<canary>"`; then, as SYS, count
--                 select count(*) from v$sqlstats where sql_text like :p
--             with :p assembled inside PL/SQL from two halves, so the counting
--             statement's own text can never match itself.
--
--     ages out?      YES. With V$SQLSTATS at its cap on this instance (~5,590
--                    rows) the canary survived 2,000 further DISTINCT statements
--                    -- `select /* sopulifine<i> */ count(*) from dual` in a
--                    loop -- and was gone by 3,000. Planted into a pool freshly
--                    emptied it lasted longer; 20,000 evicted it.
--     flush clears?  YES, immediately. Canary present before `ALTER SYSTEM FLUSH
--                    SHARED_POOL`, absent after, rows 5,575 -> 18. Run three
--                    times, the third with a password sopuli itself generated.
--     reaches AWR?   UNANSWERABLE ON XE. Two CREATE_SNAPSHOT calls succeeded and
--                    DBA_HIST_SQLTEXT *and* DBA_HIST_SQLSTAT stayed empty of
--                    everything -- control_management_pack_access is NONE on XE,
--                    so nothing is captured at all and the clean result measures
--                    the image. Needs a licensed EE with the Diagnostics Pack.
--
--   And it is not only the probe's canary. A real `sopuli creds apply` was run
--   against this image the ordinary way -- Instant Client, SOPULI_SVC holding
--   exactly 02-oracle-privileges.md sec.2's grants -- and the password it
--   generated, read back out of the vault to search for it, was there:
--
--       V$SQLSTATS.sql_text           *** LEAK *** 1
--       V$SQL.sql_text                clean        0
--       ALTER USER "ACME_APP_USER" IDENTIFIED BY "<the password sopuli generated>"
--
--   So the exposure on 11.2 is a window rather than a record, and one statement
--   removes it. That is what the decision rests on.
--
--   Two things about the container itself, both of which cost a run before they
--   were understood -- see the PROMPTs in §1 and §7:
--     - gvenzl/oracle-xe ships AUDIT_TRAIL = NONE, and captures nothing at all
--       on it. Section 4a said "NOTHING CAPTURED" until the parameter was set
--       and the container restarted.
--     - §7's grep matched the bare canary prefix, which this script's own SQL
--       text contains, so it reported a leak in audit_file_dest that was the
--       probe reading itself. Fixed to match the numbered canaries.
--
--   Note also what V$SQL_BIND_CAPTURE holds after a run: the probe's own canary
--   binds, in clear, from its own sweep queries. Nothing to do with rotation --
--   and a live demonstration of why invariant 14 exists.
--
--
-- HOW TO RUN
--   Set the DEFINEs in §0. The script connects three times: as SYSDBA to set
--   up, as the sopuli service account to issue the ALTER USER statements, then
--   back as SYSDBA to sweep. Use the same easy-connect string throughout; the
--   container is decided by the service name, so there is no ALTER SESSION SET
--   CONTAINER anywhere.
--
--   Run it in three positions and compare:
--     1. against the PDB service, svc_user = the account holding ALTER USER
--     2. against the PDB service, svc_user = sys, svc_conn_as = AS SYSDBA
--        (no privilege separation -- exercises the audit_file_dest path)
--     3. against the CDB service, common svc_user
--
--   The log file is named for the version and container automatically, so the
--   three runs do not overwrite each other.
--
--
-- CHANGES IN v3
--   - log file auto-named sopuli_leak_probe-<version>-<container>.log
--   - §3 hops to the service account for the ALTER USER statements, so the
--     rotation is performed by an account holding ALTER USER and nothing else,
--     as sopuli does. Confirms the audit policy is what captured the event
--     rather than the mandatory SYSDBA policy.
--   - audit coverage and §5 are filtered by a watermark taken before planting,
--     so repeated runs no longer accumulate. The watermark is a MAX(timestamp)
--     read, not a clock reading, which sidesteps EVENT_TIMESTAMP being UTC.
--
-- v2 fixed: trailing hyphens on PROMPT lines (SQL*Plus continuation character,
-- which silently ate the following line), COUNT() on CLOB raising ORA-22849,
-- DBA_PRIV_AUDIT_OPTS losing AUDIT_OPTION on 23ai+, FLUSH_UNIFIED_AUDIT_TRAIL
-- not existing on 26ai, and the probe's own binds being reported as findings.
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- 0. Connection and canaries
--
-- svc_user must hold ALTER USER. It does not need CREATE USER or any
-- dictionary access: SYS creates and drops the test account, the service
-- account only rotates it.
--------------------------------------------------------------------------------
-- Fill these in before running. They are deliberately left as placeholders:
-- committing a working password here would put it in git history permanently,
-- and CONNECT puts it on the SQL*Plus command line and therefore into `ps`
-- (§6). Edit a local copy, or override each DEFINE on the command line.
DEFINE tns      = //localhost:1521/FREEPDB1
DEFINE sys_user = sys
DEFINE sys_pwd  = CHANGEME_SYS_PASSWORD
DEFINE svc_user = c##sopuli_svc
DEFINE svc_pwd  = CHANGEME_SVC_PASSWORD

-- The role for the section 3 hop. Empty for an ordinary service account, which
-- is the interesting case. Position 2 of HOW TO RUN sets svc_user = sys, and SYS
-- cannot connect without a role: `CONNECT sys/...@tns` is ORA-28009, which made
-- that documented position impossible to run until this existed.
DEFINE svc_conn_as = ""

-- Canaries, one per execution path, so a hit identifies WHICH path leaked.
--
--   C1  CREATE USER, literal sent by the client            (as SYSDBA)
--   C2  ALTER USER, literal sent by the client             (as svc)  <- sopuli
--   C3  ALTER USER via EXECUTE IMMEDIATE, full literal in the block   (as svc)
--   C4  ALTER USER via EXECUTE IMMEDIATE, password assembled from fragments so
--       the block text never contains the complete secret            (as svc)
--
-- C3 vs C4 is the pair that carries the argument. C3 leaking while C4 does not
-- means the retained text is the WRAPPER's, not the DDL's.
--
-- C4 being clean does NOT make fragment-splitting a defence. Both halves sit in
-- the block text and anyone reading the cursor reassembles them. C4 is a
-- control, not a technique.
--
-- The prefix and suffix are held apart in separate DEFINEs on purpose. Every
-- probe query assembles the full string inside PL/SQL, so the probe's own SQL
-- text can never match itself.
--
-- 17 bytes, alphanumeric: fits the 30-byte limit on 11.2 and the alnum_safe
-- charset default, so no quoting question is mixed into this test.
DEFINE cpfx = S0puliCanary
DEFINE c1   = S0puliCanary1Aq7x
DEFINE c2   = S0puliCanary2Bq7x
DEFINE c3   = S0puliCanary3Cq7x

SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED
SET LINESIZE 200
SET PAGESIZE 1000
SET LONG 4000
SET TRIMSPOOL ON
SET FEEDBACK OFF
SET VERIFY OFF
SET DEFINE ON
SET ECHO OFF

WHENEVER SQLERROR EXIT FAILURE
CONNECT &sys_user/"&sys_pwd"@&tns AS SYSDBA
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

-- Name the log for the version and container so three runs coexist.
-- REGEXP demands at least one dot, so it skips the marketing number ("26ai",
-- "11g") and lands on the release number.
--
-- **`CON_NAME` raises on a non-CDB, so `NVL` around it does nothing.**
-- `ORA-02003: invalid USERENV parameter`, measured on 11g XE 11.2.0.2.0 (#382).
-- The `NVL` above read as a handled absence and was not one: the SELECT failed,
-- `&logname` was never defined, and SQL*Plus then PROMPTED for it -- twice --
-- and spooled nowhere. Read in PL/SQL with a handler instead, exactly as
-- `00_install.sql` does.
--
-- Promoted from the bind to a SUBSTITUTION variable, because this script
-- CONNECTs three times and SQL*Plus clears bind variables on every CONNECT --
-- section 3's `whoami` would have printed an empty container had it stayed a
-- bind. A `DEFINE` survives, which is why every other parameter here is one.
SET TERMOUT OFF
VARIABLE probe_con VARCHAR2(128)
BEGIN
  BEGIN
    SELECT SYS_CONTEXT('USERENV','CON_NAME') INTO :probe_con FROM dual;
  EXCEPTION
    WHEN OTHERS THEN
      -- ORA-02003 only. Anything else is a real fault, and a probe that
      -- swallowed it would spool its findings to a log named after a container
      -- it never reached.
      IF SQLCODE != -2003 THEN
        RAISE;
      END IF;
      :probe_con := 'noncdb';
  END;
END;
/
COLUMN p_con NEW_VALUE con_name NOPRINT
SELECT :probe_con AS p_con FROM dual;
SET TERMOUT ON

COLUMN logname NEW_VALUE logname NOPRINT
SELECT 'sopuli_leak_probe-'
    || REGEXP_SUBSTR(banner, '\d+(\.\d+)+')
    || '-'
    || REPLACE(LOWER('&con_name'), '$', '_')
    || '.log' AS logname
  FROM v$version WHERE ROWNUM = 1;

PROMPT
PROMPT spooling to &logname

SPOOL &logname

PROMPT
PROMPT ================================================================================
PROMPT  1. Environment
PROMPT ================================================================================

COLUMN feature FORMAT A34
COLUMN value   FORMAT A70

SELECT 'banner'      AS feature, banner AS value FROM v$version WHERE ROWNUM = 1
UNION ALL SELECT 'container',    '&con_name'                             FROM dual
UNION ALL SELECT 'session user', SYS_CONTEXT('USERENV','SESSION_USER')   FROM dual
UNION ALL SELECT 'isdba',        NVL(SYS_CONTEXT('USERENV','ISDBA'),'?') FROM dual
UNION ALL SELECT 'service account under test', UPPER('&svc_user')        FROM dual
UNION ALL SELECT 'unified auditing linked in',
                 NVL((SELECT value FROM v$option WHERE parameter = 'Unified Auditing'),'n/a (11.2)')
          FROM dual;

PROMPT
PROMPT --- parameters that decide whether this test can conclude anything
COLUMN name FORMAT A34

SELECT name, value FROM v$parameter
 WHERE name IN ('audit_trail','audit_file_dest','audit_sys_operations',
                'unified_audit_sga_queue_size','diagnostic_dest',
                'sec_case_sensitive_logon','sql_trace')
 ORDER BY name;

PROMPT
PROMPT  On 11.2 to 21c: if AUDIT_TRAIL is NONE, or DB rather than DB,EXTENDED,
PROMPT  then DBA_AUDIT_TRAIL.SQL_TEXT is NULL for every statement ever executed,
PROMPT  and a clean traditional result below means nothing. The sweep reports
PROMPT  pop=n for that case rather than calling it clean. To fix, and restart:
PROMPT     ALTER SYSTEM SET audit_trail = db,extended SCOPE = SPFILE
PROMPT
PROMPT  Unquoted and two tokens. Quoting it is ORA-00096 -- "invalid value
PROMPT  DB,EXTENDED for parameter audit_trail, must be from among extended, xml,
PROMPT  none, os, db". Measured on 21c XE, 2026-09-08 (#380): this line said
PROMPT  'DB,EXTENDED' until then and had never been run.
PROMPT
PROMPT  gvenzl/oracle-xe ships AUDIT_TRAIL = NONE, and on that setting NOTHING is
PROMPT  captured -- not even the Oracle-supplied ORA_LOGON_FAILURES policy after
PROMPT  a real failed logon, measured on 21c XE. So section 4a reporting zero
PROMPT  events on a container image is the image, not the server: fix the
PROMPT  parameter, restart, and run again before concluding anything.
PROMPT
PROMPT  On 23ai and later: AUDIT_TRAIL is absent and traditional auditing is
PROMPT  desupported. ORA-46401 below is expected, not a failure. Only the
PROMPT  unified results apply.
PROMPT

--------------------------------------------------------------------------------
-- 2. Enable auditing
--
-- Note on the traditional pair: AUDIT USER is a STATEMENT option and AUDIT
-- ALTER USER is a PRIVILEGE option. They are not equivalent. Privilege auditing
-- records statements executed by virtue of holding ALTER USER, so a user
-- changing their own password with IDENTIFIED BY ... REPLACE ... -- self-rotation,
-- UC-1 Q6 -- may not be recorded by it. Both are enabled where they exist.
--------------------------------------------------------------------------------
PROMPT ================================================================================
PROMPT  2. Enabling audit policies
PROMPT ================================================================================

DECLARE
  l_cnt PLS_INTEGER;
  l_ver PLS_INTEGER;
BEGIN
  SELECT TO_NUMBER(REGEXP_SUBSTR(version, '^\d+')) INTO l_ver FROM v$instance;

  ----------------------------------------------------------------- unified ---
  IF l_ver >= 12 THEN
    BEGIN
      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM audit_unified_policies '
                     || 'WHERE policy_name = ''SOPULI_PROBE_POL''' INTO l_cnt;
      IF l_cnt = 0 THEN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY sopuli_probe_pol '
                       || 'ACTIONS CREATE USER, ALTER USER, DROP USER';
        DBMS_OUTPUT.PUT_LINE('unified     : created SOPULI_PROBE_POL');
      ELSE
        DBMS_OUTPUT.PUT_LINE('unified     : SOPULI_PROBE_POL already exists');
      END IF;

      EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM audit_unified_enabled_policies '
                     || 'WHERE policy_name = ''SOPULI_PROBE_POL''' INTO l_cnt;
      IF l_cnt = 0 THEN
        EXECUTE IMMEDIATE 'AUDIT POLICY sopuli_probe_pol';
        DBMS_OUTPUT.PUT_LINE('unified     : enabled SOPULI_PROBE_POL');
      END IF;
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE('unified     : FAILED -- ' || SQLERRM);
    END;
  ELSE
    DBMS_OUTPUT.PUT_LINE('unified     : n/a on ' || l_ver || 'x');
  END IF;

  ------------------------------------------------------------- traditional ---
  BEGIN
    EXECUTE IMMEDIATE 'AUDIT USER';
    DBMS_OUTPUT.PUT_LINE('traditional : AUDIT USER (statement option) on');
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('traditional : AUDIT USER unavailable -- '
                         || SUBSTR(SQLERRM, 1, 90));
  END;

  BEGIN
    EXECUTE IMMEDIATE 'AUDIT ALTER USER BY ACCESS';
    DBMS_OUTPUT.PUT_LINE('traditional : AUDIT ALTER USER (privilege option) on');
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('traditional : AUDIT ALTER USER unavailable -- '
                         || SUBSTR(SQLERRM, 1, 90));
  END;
END;
/

PROMPT
PROMPT --- what is actually enabled
DECLARE
  TYPE t_str IS TABLE OF VARCHAR2(400);
  v_lbl t_str := t_str('traditional statement opts',
                       'traditional privilege opts',
                       'unified enabled policies');
  v_qry t_str := t_str(
    'SELECT LISTAGG(audit_option, '', '') WITHIN GROUP (ORDER BY audit_option) '
      || 'FROM dba_stmt_audit_opts WHERE audit_option LIKE ''%USER%''',
    'SELECT LISTAGG(audit_option, '', '') WITHIN GROUP (ORDER BY audit_option) '
      || 'FROM dba_priv_audit_opts WHERE audit_option LIKE ''%USER%''',
    'SELECT LISTAGG(policy_name, '', '') WITHIN GROUP (ORDER BY policy_name) '
      || 'FROM audit_unified_enabled_policies');
  l_out VARCHAR2(4000);
BEGIN
  FOR i IN 1 .. v_lbl.COUNT LOOP
    BEGIN
      EXECUTE IMMEDIATE v_qry(i) INTO l_out;
      DBMS_OUTPUT.PUT_LINE(RPAD(v_lbl(i), 30) || NVL(l_out, '(none)'));
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE(RPAD(v_lbl(i), 30) || 'n/a  ' || SUBSTR(SQLERRM, 1, 70));
    END;
  END LOOP;
END;
/

--------------------------------------------------------------------------------
-- 3. Plant the canaries
--
-- SYS creates the account. The service account rotates it. That split is the
-- point: it is how sopuli operates, and it is the only way to show that
-- SOPULI_PROBE_POL captured the event rather than the mandatory SYSDBA policy
-- that captures everything SYS does regardless.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  3. Planting canaries
PROMPT ================================================================================

-- Watermarks, taken before planting. MAX(timestamp) rather than a clock
-- reading, so repeated runs are separated without caring whether
-- EVENT_TIMESTAMP is UTC or local.
--
-- **The unified watermark is read in PL/SQL, because 11.2 has no unified trail
-- at all.** `UNIFIED_AUDIT_TRAIL` is `ORA-00942` there, and a bare SELECT left
-- `&uat_mark` undefined -- whereupon SQL*Plus prompts for it and eats the next
-- line of the script (measured on 11g XE 11.2.0.2.0, #382). The 1900 sentinel
-- is what an empty trail already produces, so a release with no trail lands on
-- the same value by the same reasoning: nothing was captured before this run.
SET TERMOUT OFF
VARIABLE probe_uat VARCHAR2(40)
BEGIN
  BEGIN
    EXECUTE IMMEDIATE
      'SELECT TO_CHAR(NVL(MAX(event_timestamp), TIMESTAMP ''1900-01-01 00:00:00''),'
      || ' ''YYYY-MM-DD HH24:MI:SS.FF6'') FROM unified_audit_trail'
      INTO :probe_uat;
  EXCEPTION
    WHEN OTHERS THEN
      -- ORA-00942 only: there is no unified trail here. A privilege or
      -- configuration failure reading one that *does* exist would set the
      -- sentinel and make section 4a count events from every previous run,
      -- which is the separation this watermark exists to provide.
      IF SQLCODE != -942 THEN
        RAISE;
      END IF;
      :probe_uat := '1900-01-01 00:00:00.000000';
  END;
END;
/
COLUMN uat_mark NEW_VALUE uat_mark NOPRINT
SELECT :probe_uat AS uat_mark FROM dual;
SET TERMOUT ON

COLUMN dat_mark NEW_VALUE dat_mark NOPRINT
SELECT TO_CHAR(NVL(MAX(timestamp), DATE '1900-01-01'), 'YYYY-MM-DD HH24:MI:SS')
         AS dat_mark
  FROM dba_audit_trail;

PROMPT watermarks taken, this run counts only events after them

DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_users WHERE username = 'SOPULITEST';
  IF l_cnt > 0 THEN
    RAISE_APPLICATION_ERROR(-20001,
      'SOPULITEST already exists. Drop it by hand and re-run; this script '
      || 'will not touch an account it did not create.');
  END IF;
END;
/

-- C1: created by SYSDBA. sopuli never creates accounts, so this canary tests
-- the privileged path rather than the tool's path.
CREATE USER sopulitest IDENTIFIED BY "&c1";

PROMPT
PROMPT --- switching to &svc_user for the rotations
WHENEVER SQLERROR EXIT FAILURE
CONNECT &svc_user/"&svc_pwd"@&tns &svc_conn_as
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

COLUMN whoami FORMAT A100
SELECT 'connected as ' || SYS_CONTEXT('USERENV','SESSION_USER')
    || ' in ' || '&con_name'
    || ', isdba=' || NVL(SYS_CONTEXT('USERENV','ISDBA'), '?') AS whoami
  FROM dual;

PROMPT  isdba=FALSE here is the whole point. If it says TRUE, the run tells you
PROMPT  nothing about SOPULI_PROBE_POL, because mandatory auditing would have
PROMPT  captured the statements anyway.
PROMPT

-- C2: client-issued literal. This is exactly what sopuli sends.
ALTER USER sopulitest IDENTIFIED BY "&c2";

DECLARE
  l_pwd VARCHAR2(30);
BEGIN
  -- C3: the complete secret appears as a literal in this block's own text.
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY "&c3"';

  -- C4: assembled at runtime. This block's text contains the two halves but
  -- never the whole. Only the generated DDL carries the complete value.
  l_pwd := '&cpfx' || '4Dq7x';
  EXECUTE IMMEDIATE 'ALTER USER sopulitest IDENTIFIED BY "' || l_pwd || '"';
END;
/

PROMPT canaries planted (C1 create as sysdba, C2 alter, C3 exec-imm literal, C4 exec-imm assembled)

PROMPT
PROMPT --- switching back to &sys_user
WHENEVER SQLERROR EXIT FAILURE
CONNECT &sys_user/"&sys_pwd"@&tns AS SYSDBA
WHENEVER SQLERROR CONTINUE NONE
SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED

DECLARE
  l_ver PLS_INTEGER;
BEGIN
  SELECT TO_NUMBER(REGEXP_SUBSTR(version, '^\d+')) INTO l_ver FROM v$instance;
  IF l_ver >= 12 THEN
    BEGIN
      EXECUTE IMMEDIATE 'BEGIN DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;';
      DBMS_OUTPUT.PUT_LINE('unified audit trail flushed');
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE('flush unavailable on this release -- section 4a decides '
                           || 'whether that mattered');
    END;
  END IF;
END;
/

--------------------------------------------------------------------------------
-- 4a. Audit coverage
--
-- Read this before the sweep. "No canary found" is only a result if something
-- was captured and the text column was populated.
--
-- DBUSERNAME is printed because it is the evidence that the policy, not the
-- mandatory SYSDBA policy, did the capturing: the three ALTER USER rows should
-- name the service account.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  4a. Audit coverage for SOPULITEST, this run only
PROMPT ================================================================================

DECLARE
  TYPE t_str IS TABLE OF VARCHAR2(600);
  v_lbl t_str := t_str('UNIFIED_AUDIT_TRAIL', 'DBA_AUDIT_TRAIL');
  v_qry t_str := t_str(
    'SELECT COUNT(*), COUNT(CASE WHEN sql_text IS NOT NULL THEN 1 END) '
      || 'FROM unified_audit_trail WHERE object_name = ''SOPULITEST'' '
      || 'AND event_timestamp > TO_TIMESTAMP(''&uat_mark'', ''YYYY-MM-DD HH24:MI:SS.FF6'')',
    'SELECT COUNT(*), COUNT(CASE WHEN sql_text IS NOT NULL THEN 1 END) '
      || 'FROM dba_audit_trail WHERE obj_name = ''SOPULITEST'' '
      || 'AND timestamp > TO_DATE(''&dat_mark'', ''YYYY-MM-DD HH24:MI:SS'')');
  l_rows NUMBER;
  l_txt  NUMBER;
BEGIN
  FOR i IN 1 .. v_lbl.COUNT LOOP
    BEGIN
      EXECUTE IMMEDIATE v_qry(i) INTO l_rows, l_txt;
      DBMS_OUTPUT.PUT_LINE(
        RPAD(v_lbl(i), 24) || 'events=' || LPAD(l_rows, 4)
        || '  with sql_text=' || LPAD(l_txt, 4)
        || CASE WHEN l_rows = 0 THEN '   <<< NOTHING CAPTURED - this trail proves nothing'
                WHEN l_txt  = 0 THEN '   <<< SQL_TEXT NULL - this trail proves nothing'
                ELSE '   ok' END);
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE(RPAD(v_lbl(i), 24) || 'n/a  ' || SUBSTR(SQLERRM, 1, 70));
    END;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('expected: 4 events (1 CREATE USER by sysdba + 3 ALTER USER by the service account)');
END;
/

--------------------------------------------------------------------------------
-- 4b. The sweep
--
-- Every place a statement's text can come to rest. Sources absent on this
-- version report n/a rather than failing, so one script covers 11.2 to 26ai.
--
-- Each line carries pop=y/n: whether the column is populated at all in this
-- database. A "clean" on a pop=n column is not a clean, it is an absence of
-- evidence, and it is labelled INCONCLUSIVE.
--
-- Self-contamination is handled three ways: canaries are assembled from halves
-- inside this block so the block cannot match itself; comparison values are
-- passed as binds so no child cursor carries a literal; and the generated SQL
-- carries a /* SOPULI_PROBE */ marker so V$SQL_BIND_CAPTURE can exclude the
-- probe's own binds.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  4b. Canary sweep
PROMPT ================================================================================

DECLARE
  TYPE t_probe  IS RECORD (src VARCHAR2(200), col VARCHAR2(100), extra VARCHAR2(400));
  TYPE t_probes IS TABLE OF t_probe INDEX BY PLS_INTEGER;
  TYPE t_str    IS TABLE OF VARCHAR2(64);

  v     t_probes;
  n     PLS_INTEGER := 0;
  v_sfx t_str := t_str('1Aq7x', '2Bq7x', '3Cq7x', '4Dq7x');
  c_pfx CONSTANT VARCHAR2(30) := '&cpfx';

  -- excludes cursors belonging to this sweep
  c_notme CONSTANT VARCHAR2(300) :=
    'sql_id NOT IN (SELECT sql_id FROM v$sql WHERE INSTR(sql_text, ''SOPULI_PROBE'') > 0)';

  l_cnt   NUMBER;
  l_pop   NUMBER;
  l_hits  VARCHAR2(200);
  l_total PLS_INTEGER := 0;

  PROCEDURE add(p_src VARCHAR2, p_col VARCHAR2, p_extra VARCHAR2 DEFAULT NULL) IS
  BEGIN
    n := n + 1; v(n).src := p_src; v(n).col := p_col; v(n).extra := p_extra;
  END;
BEGIN
  add('V$SQL',                  'sql_text');
  add('V$SQL',                  'sql_fulltext');
  add('V$SQLAREA',              'sql_text');
  add('V$SQLAREA',              'sql_fulltext');
  add('V$SQLSTATS',             'sql_text');
  add('V$SQLSTATS',             'sql_fulltext');
  add('GV$SQL',                 'sql_fulltext');
  add('V$OPEN_CURSOR',          'sql_text');
  add('V$SQL_BIND_CAPTURE',     'value_string', c_notme);
  add('V$DB_OBJECT_CACHE',      'name');
  add('V$DIAG_ALERT_EXT',       'message_text');
  add('DBA_HIST_SQLTEXT',       'sql_text');
  add('DBA_SQL_PLAN_BASELINES', 'sql_text');
  add('DBA_SQLSET_STATEMENTS',  'sql_text');
  add('UNIFIED_AUDIT_TRAIL',    'sql_text');
  add('UNIFIED_AUDIT_TRAIL',    'sql_binds');
  add('AUDSYS.AUD$UNIFIED',     'sql_text');
  add('AUDSYS.AUD$UNIFIED',     'sql_binds');
  add('DBA_AUDIT_TRAIL',        'sql_text');
  add('DBA_AUDIT_TRAIL',        'sql_bind');
  add('SYS.AUD$',               'sqltext');
  add('SYS.AUD$',               'sqlbind');
  add('DBA_COMMON_AUDIT_TRAIL', 'sql_text');
  add('DBA_FGA_AUDIT_TRAIL',    'sql_text');

  DBMS_OUTPUT.PUT_LINE(RPAD('source.column', 42) || RPAD('pop', 7) || 'result');
  DBMS_OUTPUT.PUT_LINE(RPAD('-', 42, '-') || RPAD('-', 7, '-') || RPAD('-', 40, '-'));

  FOR i IN 1 .. n LOOP
    BEGIN
      -- is this column populated at all? ROWNUM<=1 keeps it cheap on V$SQL.
      EXECUTE IMMEDIATE
        'SELECT COUNT(*) FROM (SELECT /* SOPULI_PROBE */ 1 FROM ' || v(i).src
        || ' WHERE ' || v(i).col || ' IS NOT NULL'
        || CASE WHEN v(i).extra IS NOT NULL THEN ' AND ' || v(i).extra END
        || ' AND ROWNUM <= 1)'
        INTO l_pop;

      l_hits := NULL;
      FOR j IN 1 .. v_sfx.COUNT LOOP
        EXECUTE IMMEDIATE
          'SELECT /* SOPULI_PROBE */ COUNT(*) FROM ' || v(i).src
          || ' WHERE INSTR(UPPER(' || v(i).col || '), UPPER(:b)) > 0'
          || CASE WHEN v(i).extra IS NOT NULL THEN ' AND ' || v(i).extra END
          INTO l_cnt USING c_pfx || v_sfx(j);
        IF l_cnt > 0 THEN
          l_hits  := l_hits || ' C' || j || '(' || l_cnt || ')';
          l_total := l_total + 1;
        END IF;
      END LOOP;

      DBMS_OUTPUT.PUT_LINE(
        RPAD(v(i).src || '.' || v(i).col, 42)
        || RPAD(CASE WHEN l_pop > 0 THEN 'y' ELSE 'n' END, 7)
        || CASE WHEN l_hits IS NOT NULL THEN '*** LEAK ***' || l_hits
                WHEN l_pop > 0          THEN 'clean'
                ELSE 'INCONCLUSIVE - column never populated here' END);
    EXCEPTION WHEN OTHERS THEN
      DBMS_OUTPUT.PUT_LINE(RPAD(v(i).src || '.' || v(i).col, 42)
                           || RPAD('-', 7) || 'n/a  ' || SUBSTR(SQLERRM, 1, 60));
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE(RPAD('-', 89, '-'));
  DBMS_OUTPUT.PUT_LINE('findings: ' || l_total
    || CASE WHEN l_total > 0
            THEN '  -- triage each in section 5 before writing it up'
            ELSE '  -- check every pop=n line before calling this a pass' END);
END;
/

--------------------------------------------------------------------------------
-- 5. What Oracle actually stored
--
-- The counts answer "is the secret there". This answers "what shape did Oracle
-- keep" -- masked, elided, replaced by a verifier, or never retained at all.
-- Those are four different security stories, and on 26ai the answer differs
-- between the two mechanisms: the audit trail masks, the shared pool omits.
--
-- Also the triage surface for §4b.
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  5. Retained statement text
PROMPT ================================================================================

COLUMN sql_id FORMAT A15
COLUMN txt    FORMAT A130 WORD_WRAPPED

PROMPT
PROMPT --- V$SQL: every cursor mentioning the test account, excluding this probe
PROMPT     An empty result here means the DDL was never retained, which is a
PROMPT     stronger outcome than being retained and masked.
SELECT sql_id, SUBSTR(sql_text, 1, 400) AS txt
  FROM v$sql
 WHERE UPPER(sql_text) LIKE '%SOPULITEST%'
   AND INSTR(sql_text, 'SOPULI_PROBE') = 0
 ORDER BY last_active_time;

PROMPT
PROMPT --- V$SQL_BIND_CAPTURE: which cursor owns each captured canary bind
COLUMN val       FORMAT A24
COLUMN owner_txt FORMAT A100 WORD_WRAPPED

SELECT bc.sql_id,
       SUBSTR(bc.value_string, 1, 24) AS val,
       SUBSTR(s.sql_text, 1, 100)     AS owner_txt
  FROM v$sql_bind_capture bc
       LEFT JOIN v$sql s
         ON s.sql_id = bc.sql_id AND s.child_number = bc.child_number
 WHERE UPPER(bc.value_string) LIKE '%CANARY%'
 ORDER BY bc.sql_id;

PROMPT
PROMPT --- UNIFIED_AUDIT_TRAIL: this run's user-management events
PROMPT     DBUSERNAME on the ALTER USER rows should be the service account.
COLUMN ts          FORMAT A16
COLUMN dbusername  FORMAT A18
COLUMN action_name FORMAT A13
COLUMN object_name FORMAT A12

SELECT TO_CHAR(event_timestamp, 'HH24:MI:SS.FF3') AS ts,
       dbusername, action_name, object_name,
       SUBSTR(sql_text, 1, 120) AS txt
  FROM unified_audit_trail
 WHERE object_name = 'SOPULITEST'
   AND event_timestamp > TO_TIMESTAMP('&uat_mark', 'YYYY-MM-DD HH24:MI:SS.FF6')
 ORDER BY event_timestamp;

PROMPT
PROMPT --- DBA_AUDIT_TRAIL: same, for 11.2 and mixed mode
COLUMN username FORMAT A18
COLUMN obj_name FORMAT A12

SELECT TO_CHAR(timestamp, 'HH24:MI:SS') AS ts,
       username, action_name, obj_name,
       SUBSTR(sql_text, 1, 120) AS txt
  FROM dba_audit_trail
 WHERE obj_name = 'SOPULITEST'
   AND timestamp > TO_DATE('&dat_mark', 'YYYY-MM-DD HH24:MI:SS')
 ORDER BY timestamp;

--------------------------------------------------------------------------------
-- 6. Optional extensions, left manual
--
-- 6a. Self-rotation (UC-1 Q6). The path where the account changes its OWN
--     password and therefore does not exercise the ALTER USER privilege.
--     Privilege auditing can miss this while statement auditing catches it --
--     worth knowing before the docs claim "rotations are audited".
--
--       CONNECT sopulitest/"S0puliCanary4Dq7x"@&tns
--       ALTER USER sopulitest IDENTIFIED BY "S0puliCanary5Eq7x"
--                             REPLACE "S0puliCanary4Dq7x";
--
--     Then re-run §4b with a C5 suffix added.
--
-- 6b. IDENTIFIED BY VALUES. Not a sopuli code path today, but it would be the
--     restore-from-verifier path if one is ever added, and the redaction
--     question is separate: Oracle masks a password, but does it mask a
--     verifier? Offline-crackable either way.
--
--       SELECT spare4 FROM sys.user$ WHERE name = 'SOPULITEST';
--       ALTER USER sopulitest IDENTIFIED BY VALUES '<that string>';
--       SELECT sql_text FROM v$sql WHERE UPPER(sql_text) LIKE '%SOPULITEST%';
--
--     Needs SELECT ON SYS.USER$, itself an open question (ADR-001).
--
-- Note that CONNECT puts the password on the SQL*Plus command line, so it is in
-- ps output on a shared host. So are the DEFINEs in §0 of this script. Both are
-- findings for the README about operating sopuli, not about Oracle.
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- 7. What SQL cannot reach
--------------------------------------------------------------------------------
PROMPT
PROMPT ================================================================================
PROMPT  7. Off-database checks, run these on the server
PROMPT ================================================================================

-- The pattern is the canary PREFIX PLUS A DIGIT, never the bare prefix.
--
-- Measured on 21c, 2026-09-08 (#380): with AUDIT_SYS_OPERATIONS = TRUE the bare
-- prefix always matches, because this script's own text contains it -- section
-- 4b's `c_pfx CONSTANT VARCHAR2(30) := '<prefix>'` and these four PROMPT lines
-- are themselves SQL that a SYSDBA session executes, so they land in
-- audit_file_dest and the grep finds itself. It reads as a leak in the one place
-- where a leak would matter most, which is the worst possible false positive.
--
-- The whole reason §0 holds the prefix and the suffix apart in separate DEFINEs
-- is that the probe's own SQL text must never match itself. Printing the bare
-- prefix here undid that. `[0-9]` restores it: C1 to C4 are the planted
-- passwords, the prefix alone is this script talking about them.
SET HEADING OFF
SELECT '  grep -rlE ''&cpfx.[0-9]'' ' || value || '/     # trace files, 10046, incident dumps'
  FROM v$diag_info WHERE name = 'Diag Trace'
UNION ALL
SELECT '  grep -rlE ''&cpfx.[0-9]'' ' || value || '/     # OS audit files, the SYSDBA path'
  FROM v$parameter WHERE name = 'audit_file_dest'
UNION ALL
SELECT '  grep -rlE ''&cpfx.[0-9]'' $ORACLE_BASE/diag/tnslsnr/*/*/     # listener log'
  FROM dual
UNION ALL
SELECT '  grep -rlE ''&cpfx.[0-9]'' ~/.sqlplus_history 2>/dev/null     # client history'
  FROM dual;
SET HEADING ON

PROMPT
PROMPT  A hit names the file; grep the numbered canary again inside it to see
PROMPT  WHICH path leaked. A match on the bare prefix and none on a numbered
PROMPT  canary is this script's own text, not a password -- see the comment on
PROMPT  the query above.
PROMPT
PROMPT  The audit_file_dest grep tests the SYSDBA path specifically, so it is
PROMPT  answered by the C1 canary in this run rather than by C2 to C4. Run the
PROMPT  script once with svc_user = sys to exercise it properly. It matters most
PROMPT  on 11.2, where AUDIT_SYS_OPERATIONS writes statement text to plain files
PROMPT  that no query in this script can see.
PROMPT
PROMPT  DBA_HIST_SQLTEXT is only populated after an AWR snapshot and needs the
PROMPT  Diagnostics Pack. If it reported clean, take a snapshot and re-run 4b
PROMPT  before believing it.
PROMPT

--------------------------------------------------------------------------------
-- 8. Cleanup
--
-- The account and the policies go. The audit records deliberately DO NOT --
-- they are the evidence. Purge them once the findings are written up.
--------------------------------------------------------------------------------
PROMPT ================================================================================
PROMPT  8. Cleanup
PROMPT ================================================================================

DECLARE
  l_ver PLS_INTEGER;
BEGIN
  BEGIN
    EXECUTE IMMEDIATE 'DROP USER sopulitest CASCADE';
    DBMS_OUTPUT.PUT_LINE('dropped SOPULITEST');
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('drop failed -- ' || SQLERRM);
  END;

  BEGIN EXECUTE IMMEDIATE 'NOAUDIT USER';       EXCEPTION WHEN OTHERS THEN NULL; END;
  BEGIN EXECUTE IMMEDIATE 'NOAUDIT ALTER USER'; EXCEPTION WHEN OTHERS THEN NULL; END;

  SELECT TO_NUMBER(REGEXP_SUBSTR(version, '^\d+')) INTO l_ver FROM v$instance;
  IF l_ver >= 12 THEN
    BEGIN EXECUTE IMMEDIATE 'NOAUDIT POLICY sopuli_probe_pol';    EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN EXECUTE IMMEDIATE 'DROP AUDIT POLICY sopuli_probe_pol'; EXCEPTION WHEN OTHERS THEN NULL; END;
    DBMS_OUTPUT.PUT_LINE('dropped SOPULI_PROBE_POL');
  END IF;

  DBMS_OUTPUT.PUT_LINE('audit records LEFT IN PLACE -- purge after writing up section 5');
END;
/

PROMPT
PROMPT  When finished, purge the planted records. Destructive, review first.
PROMPT
PROMPT     BEGIN
PROMPT       DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(
PROMPT         audit_trail_type        => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
PROMPT         use_last_arch_timestamp => FALSE)
PROMPT     END
PROMPT     /
PROMPT
PROMPT  Never DELETE FROM AUDSYS.AUD$UNIFIED by hand. Same class of mistake as
PROMPT  deleting vault lock records instead of writing a released state: it
PROMPT  leaves the surrounding bookkeeping inconsistent in ways that only show
PROMPT  up on the next cycle.
PROMPT
PROMPT  Then delete the spool, which holds all four canaries in clear.
PROMPT

SPOOL OFF
