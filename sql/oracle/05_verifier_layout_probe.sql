--------------------------------------------------------------------------------
-- sopuli-dba : password verifier layout probe   (v1)
--
-- STATUS: run on 26ai Free 23.26.2.0.0 (FREEPDB1), 21c XE 21.3.0.0.0 (XEPDB1),
-- 18c XE 18.4.0.0.0 (XEPDB1) and 11g XE 11.2.0.2.0 on 2026-09-15 (#431), twice
-- each, with the §5 trace step run on all four. **Untried on 19c, 12.1 and
-- 12.2** -- and 19c is the release #431 names first. Nothing below says what 19c
-- stores; read every result as "these four releases do".
--
-- Part 1 of #90's spike (#431). It READS what Oracle stores in SYS.USER$.SPARE4
-- and SYS.USER$.PASSWORD and names the fields. It derives nothing: whether a
-- client can regenerate a verifier from a known password is #432, and it needs
-- this file's field table to be attempted at all.
--
-- THROWAWAY DATABASES ONLY. Creates ACME_VFR_USER with known passwords, and
-- leaves it in place so §5's traced logon has an account to log in as. The
-- verifiers it prints are offline-crackable for passwords printed next to them,
-- which is harmless for a test account and is the reason this never runs
-- anywhere else.
--
--
-- RESULTS
--   Identical on 26ai, 21c and 18c. 11g differs only by carrying no T: at all.
--
--   1. SPARE4 LAYOUT. Verifiers are separated by ';', each introduced by a
--      two-character prefix. The order is S: then T:. There is NO H: in SPARE4
--      on any of the four -- the 10G verifier lives in SYS.USER$.PASSWORD.
--
--        release   PASSWORD_VERSIONS   SPARE4                       USER$.PASSWORD
--        26ai      11G 12C             S:<60 hex>;T:<160 hex>  225  (null)
--        21c       11G 12C             S:<60 hex>;T:<160 hex>  225  (null)
--        18c       11G 12C             S:<60 hex>;T:<160 hex>  225  (null)
--        11g       10G 11G             S:<60 hex>               62  16 hex
--
--      Field table, all hex is upper case:
--
--        field  hex   bytes  layout (offsets in hex characters after the prefix)
--        S:     60    30     [0,40)  20-byte digest   [40,60)   10-byte salt
--        T:     160   80     [0,128) 64-byte digest   [128,160) 16-byte salt
--        10G    16    8      whole value; no salt
--
--      The salt offsets are MEASURED, not assumed. §5 traces a logon and reads
--      AUTH_VFR_DATA -- the salt the server sends the client -- off the wire.
--      On every release it equals the last 32 hex of T: (12.2+) or the last 20
--      hex of S: (11g), character for character. Run 1, §4 against §5:
--
--        26ai  §4  T:53073E11...F85BC6B3 salt=FE7CB8920A2CA10011B183CCD944413A
--              §5  AUTH_VFR_DATA.....FE7CB8920A2CA10011B183CCD944413A
--        21c   §4  T:A3A36D1F...8541DF66 salt=ECE896BEF4985CAAB101034505FEB916
--              §5  AUTH_VFR_DATA.....ECE896BEF4985CAAB101034505FEB916
--        18c   §4  T:2D71AE37...EDB6C06E salt=15FEB75DC0A667521C39F9E10C945828
--              §5  AUTH_VFR_DATA.....15FEB75DC0A667521C39F9E10C945828
--        11g   §4  S:BAFAD5A5...CC93FFDF salt=33B179CB7366EA0029A0
--              §5  AUTH_VFR_DATA.....33B179CB7366EA0029A0
--
--      Run 2 drew a new salt on every release and matched again. The trace
--      matters because nothing in SPARE4 marks where a salt starts: a split
--      at any other offset would print just as tidily.
--
--      THE ITERATION COUNT IS NOT STORED IN SPARE4. Nothing in the 160 hex
--      varies except digest and salt. The server SENDS it at logon instead, on
--      all three 12.2+ releases:
--
--        AUTH_PBKDF2_VGEN_COUNT  4096   (verifier generation)
--        AUTH_PBKDF2_SDER_COUNT  3      (session key derivation, not stored)
--        AUTH_PBKDF2_CSK_SALT    32 hex, fresh per logon (not stored)
--
--      11g sends AUTH_VFR_DATA alone and no AUTH_PBKDF2_* key. What the digest
--      is a digest OF -- how 4096 and the salt combine with the password -- is
--      #432's question and this file does not attempt it.
--
--   2. EVERY SET DRAWS A NEW SALT. Setting the same password again replaces
--      S: and T: completely -- digest and salt both -- on all four releases.
--      So a stored verifier cannot be compared by equality with one from
--      another set; any comparison has to regenerate from THIS salt.
--
--   3. NORMALISATION -- what can be observed without deriving:
--      - The client's bytes arrive as sent. §0's DUMP() of the non-ASCII
--        literal is c3,84,...,c3,b6 (UTF-8) on all four under
--        NLS_LANG=AMERICAN_AMERICA.AL32UTF8; all four databases are AL32UTF8.
--        Under any other client charset this is not guaranteed, and #432's
--        non-ASCII case must pin it the same way.
--      - S: and T: are salted, so case folding in them is NOT observable here.
--        "Acme-Probe-1" and "acme-probe-1" give different blobs, but so does
--        "Acme-Probe-1" twice (item 2). #432 answers it by regenerating.
--      - The 10G value is unsalted, so its folding IS observable (11g only):
--
--          Acme-Probe-1  acme-probe-1  Äcme-Pröbe-1  äcme-Probe-1   C959D5A13E2B56A2
--          Écme-Probe-1  Ecme-Probe-1                               34439E32B6D98134
--          Ñcme-Probe-1                                             8A529C6AC2FCB449
--          Ncme-Probe-1                                             7495809E9F116855
--          Bcme-Probe-1                                             D23F516808EECB24
--
--        Case-insensitive, and some -- not all -- diacritics fold to their
--        base letter: Ä, Ö, É do; Ñ does not. It also depends on the user name
--        (the same password as ACME_VFX_USER gives 0F06BCB08C4BDFC4). There is no
--        rule to write down from five letters, and nothing needs one: 10G is
--        not a verifier sopuli compares (#433).
--
--   4. SEC_CASE_SENSITIVE_LOGON. Absent from V$PARAMETER on 26ai and 21c;
--      present and TRUE on 18c and 11g. Flipped to FALSE on 11g only, by hand
--      (MANUAL STEP below): S: is still regenerated with a fresh salt and the
--      10G value is unchanged (it was already case-insensitive). So the
--      parameter changes nothing observable in what is STORED. Whether it
--      changes what S: is computed over is, again, #432's. Not flipped on 18c:
--      on 12.2+ with ALLOWED_LOGON_VERSION_SERVER=12 it disables every non-SYS
--      logon, and the question is pre-12.2 anyway.
--
--
-- HOW TO RUN
--   As SYSDBA, in the container the test account should live in, with a UTF-8
--   client so §3's non-ASCII password reaches the server as the bytes written
--   here. SYSDBA rather than a list of grants: the script drops, creates and
--   repeatedly alters ACME_VFR_USER, grants it CREATE SESSION, switches
--   container, and reads SYS.USER$, DBA_USERS and V$PDBS -- and the MANUAL STEP
--   changes a system parameter. Reading SYS.USER$ alone, the §2 grant in
--   02-oracle-privileges.md, is enough to read a layout but not to run this.
--
--     export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
--     sqlplus -s "/ as sysdba" @05_verifier_layout_probe.sql
--
--   Against the test stack (docker compose --profile tier2, from test/), for
--   example:
--
--     docker exec -i -e NLS_LANG=AMERICAN_AMERICA.AL32UTF8 \
--       sopuli-test-oracle-free-1 sqlplus -s / as sysdba \
--       < sql/oracle/05_verifier_layout_probe.sql
--
--   The script switches to FREEPDB1 / XEPDB1 itself when it finds one, and
--   stays put on a non-CDB. §5 prints the shell commands for the traced logon;
--   run them in the same container. Re-running drops and recreates the account.
--
--
-- MANUAL STEP -- SEC_CASE_SENSITIVE_LOGON (item 4, pre-12.2 only)
--   Not scripted: it is a system-wide parameter and the finding is a negative.
--   What was run on 11g, between §1 and §3:
--
--     ALTER SYSTEM SET sec_case_sensitive_logon = FALSE;
--     ALTER USER acme_vfr_user IDENTIFIED BY "Acme-Probe-1";   -- then read §2
--     ALTER USER acme_vfr_user IDENTIFIED BY "acme-probe-1";   -- then read §2
--     ALTER SYSTEM SET sec_case_sensitive_logon = TRUE;
--------------------------------------------------------------------------------

SET PAGESIZE 0 LINESIZE 400 FEEDBACK OFF HEADING OFF VERIFY OFF TRIMSPOOL ON
-- Nothing here is a substitution variable, and §5 prints shell text containing
-- `&&`. With DEFINE on, that prompts for a variable named after the next word
-- and the quoting after it comes apart -- measured, not guessed: the first run
-- printed none of §5's commands, and its grep then found no trace to read.
SET DEFINE OFF
SET SERVEROUTPUT ON

--------------------------------------------------------------------------------
-- §0  Where this is running
--------------------------------------------------------------------------------
-- Moves into the one application PDB the test images ship, if there is one. A
-- non-CDB has no V$PDBS rows worth using and stays where it is. The statement is
-- built at runtime so that 11g, which has no V$PDBS, does not fail to parse it.
DECLARE
  l_pdb     VARCHAR2(128);
  no_view   EXCEPTION;
  PRAGMA EXCEPTION_INIT(no_view, -942);
BEGIN
  EXECUTE IMMEDIATE
    q'[SELECT MIN(name) FROM v$pdbs WHERE name IN ('FREEPDB1', 'XEPDB1')]'
    INTO l_pdb;
  IF l_pdb IS NOT NULL THEN
    EXECUTE IMMEDIATE 'ALTER SESSION SET CONTAINER = ' || l_pdb;
  END IF;
EXCEPTION
  WHEN no_view THEN
    NULL;  -- 11g: no V$PDBS, so a non-CDB, and nothing to switch to
END;
/

PROMPT
PROMPT == §0  release
SELECT 'version                   ' || version FROM v$instance;
SELECT 'container                 ' || SYS_CONTEXT('USERENV', 'DB_NAME') FROM dual;
SELECT 'database charset          ' || value
  FROM nls_database_parameters WHERE parameter = 'NLS_CHARACTERSET';
-- No row at all on 21c and 26ai: the parameter is gone, not merely defaulted.
SELECT 'sec_case_sensitive_logon  ' || NVL(MAX(value), '(no such parameter)')
  FROM v$parameter WHERE name = 'sec_case_sensitive_logon';
-- If this is not c3,84,...,c3,b6 the client is not sending UTF-8, and §3's
-- non-ASCII row is measuring the client's charset conversion, not Oracle.
SELECT 'non-ascii literal bytes   ' || DUMP('Äcme-Pröbe-1', 16) FROM dual;

--------------------------------------------------------------------------------
-- §1  The account
--------------------------------------------------------------------------------
WHENEVER SQLERROR CONTINUE
DROP USER acme_vfr_user CASCADE;
WHENEVER SQLERROR EXIT FAILURE
CREATE USER acme_vfr_user IDENTIFIED BY "Acme-Probe-1";
GRANT CREATE SESSION TO acme_vfr_user;

--------------------------------------------------------------------------------
-- §2  One read, used after every set below
--------------------------------------------------------------------------------
-- The same read follows every set, written out in full each time. It prints
-- the whole of SPARE4 with each verifier on its own line and a space before the
-- salt at the offset §5 measured -- so a changed offset on some other release
-- shows up as a salt= that no longer matches AUTH_VFR_DATA, rather than being
-- hidden by a cut into columns.
--
-- Repeated rather than DEFINEd, and that was learned by running it: SQL*Plus
-- decides what kind of line it is reading BEFORE substituting, so a line that
-- is only `&vfr_read;` is SP2-0042 and reads nothing. A view would do it too,
-- but would mean creating an object in SYS.

PROMPT
PROMPT == §2  after CREATE USER ... "Acme-Probe-1"
SELECT 'password_versions=[' || password_versions || ']'
  FROM dba_users WHERE username = 'ACME_VFR_USER';
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';

--------------------------------------------------------------------------------
-- §3  Sets, each issued directly -- never inside a PL/SQL block (invariant 13)
--------------------------------------------------------------------------------
PROMPT
PROMPT == §3a  the same password again -- does anything survive? (it does not)
ALTER USER acme_vfr_user IDENTIFIED BY "Acme-Probe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';

PROMPT
PROMPT == §3b  lower case
ALTER USER acme_vfr_user IDENTIFIED BY "acme-probe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';

PROMPT
PROMPT == §3c  non-ASCII (check §0's byte dump first)
ALTER USER acme_vfr_user IDENTIFIED BY "Äcme-Pröbe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';

-- The 10G value is unsalted, so these pairs are comparable by eye. On 12.2+ it
-- is null and the rows show 10G=[] -- expected, not a failure.
PROMPT
PROMPT == §3d  10G folding pairs (11g only carries a 10G value)
ALTER USER acme_vfr_user IDENTIFIED BY "Écme-Probe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';
ALTER USER acme_vfr_user IDENTIFIED BY "Ecme-Probe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';
ALTER USER acme_vfr_user IDENTIFIED BY "Ñcme-Probe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';
ALTER USER acme_vfr_user IDENTIFIED BY "Ncme-Probe-1";
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';

--------------------------------------------------------------------------------
-- §4  Back to a known password, for §5
--------------------------------------------------------------------------------
ALTER USER acme_vfr_user IDENTIFIED BY "Acme-Probe-1";
PROMPT
PROMPT == §4  final state -- §5's AUTH_VFR_DATA must equal the salt printed here
SELECT 'len=' || LENGTH(spare4) || ' 10G=[' || password || ']' || CHR(10)
       || REGEXP_REPLACE(REGEXP_REPLACE(REPLACE(spare4, ';', CHR(10)),
            '(T:.{128})', '\1 salt='), '(S:.{40})', '\1 salt=')
  FROM sys.user$ WHERE name = 'ACME_VFR_USER';

--------------------------------------------------------------------------------
-- §5  The salt, off the wire
--------------------------------------------------------------------------------
-- SQL cannot see what the server sends a client, so this is printed rather than
-- run. DIAG_ADR_ENABLED=OFF is not optional: with ADR on, a client ignores
-- TRACE_DIRECTORY_CLIENT and writes under $ORACLE_BASE/diag, and the grep finds
-- nothing -- which reads as "no AUTH_VFR_DATA sent", exactly wrong.
--
-- The trace is a hex dump eight bytes to a line, so a key name is split across
-- lines at a different offset in every packet. The pipeline rejoins the ASCII
-- column before matching; grepping the file directly misses the key.
PROMPT
PROMPT == §5  run these in the same container, then compare with §4's salt=
SELECT '  mkdir -p /tmp/vfrtns && printf ''DIAG_ADR_ENABLED=OFF\nTRACE_LEVEL_CLIENT=16\nTRACE_DIRECTORY_CLIENT=/tmp/vfrtns\n'' > /tmp/vfrtns/sqlnet.ora'
  FROM dual;
SELECT '  echo exit | TNS_ADMIN=/tmp/vfrtns sqlplus -s -L ''acme_vfr_user/"Acme-Probe-1"@//localhost:1521/'
       || SYS_CONTEXT('USERENV', 'DB_NAME') || ''''
  FROM dual;
SELECT '  grep -h ''nsbasic_brc: '' /tmp/vfrtns/*.trc | sed -n ''s/.*|\(.\{1,8\}\)|$/\1/p'' | tr -d ''\n'' \' FROM dual;
SELECT '    | grep -oE ''AUTH_(VFR_DATA|PBKDF2_[A-Z_]+)\.{1,8}[0-9A-F]+'' | sort -u' FROM dual;
PROMPT
PROMPT  Expect AUTH_VFR_DATA = §4's T: salt on 12.2+, or its S: salt on 11g, plus
PROMPT  AUTH_PBKDF2_VGEN_COUNT / SDER_COUNT / CSK_SALT on 12.2+ only.
PROMPT
PROMPT  Clean up afterwards:  DROP USER acme_vfr_user CASCADE;  rm -rf /tmp/vfrtns

EXIT
