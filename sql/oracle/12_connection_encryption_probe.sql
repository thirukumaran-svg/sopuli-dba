--------------------------------------------------------------------------------
-- sopuli-dba : can a session tell whether its own connection is encrypted?   (v1)
--
-- #697. The tool sends ALTER USER ... IDENTIFIED BY "..." over its connection,
-- so on an unencrypted connection the new password crosses the network in
-- clear. `sopuli doctor` should report whether each connection is encrypted,
-- and by what. This measures what a session can read about its own connection,
-- with and without a grant:
--
--   EN0  who holds a grant on SYS.V_$SESSION_CONNECT_INFO
--   EN1  as an account holding only CREATE SESSION: the USERENV attribute
--        NETWORK_PROTOCOL
--   EN2  the same account reads V$SESSION_CONNECT_INFO: every
--        NETWORK_SERVICE_BANNER row of its own SID, and how many SIDs the view
--        shows it
--   EN3  after SYS grants SELECT on SYS.V_$SESSION_CONNECT_INFO to the
--        account, the same read
--
-- The script is the same for each case. What changes is the client's network
-- configuration, which TNS_ADMIN points at, and the connect string (HOW TO RUN).
--
-- This MEASURES and decides nothing. What doctor reports is #697.
--
-- STATUS: run 2026-10-09 on 26ai Free 23.26.2.0.0 (FREEPDB1), 21c XE 21.3.0.0.0
-- and 18c XE 18.4.0.0.0 (XEPDB1), 11g XE 11.2.0.2.0 (SID XE), 19c EE 19.3.0.0.0
-- (ORCLPDB1) and 12c EE 12.2.0.1.0 (orclpdb1.localdomain), each in three client
-- configurations: plain TCP, NNE required by the client (AES256), and TLS to
-- a TCPS listener endpoint with a self-signed throwaway wallet. TLS on
-- 11.2.0.2.0 did not run: the client refused both wallets tried with ORA-29106
-- (cannot import PKCS #12 wallet).
--
--
-- RESULTS -- every release above, 2026-10-09
--
--   EN0  PUBLIC holds READ on V_$SESSION_CONNECT_INFO (SELECT on 11.2.0.2.0).
--        No other grantee
--   EN1  `tcp` on a TCP connection, NNE or not; `tcps` on a TLS connection
--   EN2  readable with no grant to the account. The banner rows of a session:
--
--          plain TCP  TCP/IP NT Protocol Adapter for Linux: Version ...
--                     Encryption service for Linux: Version ...
--                     Crypto-checksumming service for Linux: Version ...
--                     (11.2.0.2.0 prefixes the last two with "Oracle Advanced
--                     Security: " and writes them in lower case)
--          NNE        the same, plus one row naming the algorithm:
--                       AES256 Encryption service adapter for Linux: Version ...
--                     and on 11.2.0.2.0:
--                       Oracle Advanced Security: AES256 encryption service
--                       adapter for Linux: Version ...
--
--        The "Encryption service for Linux" row is there on every connection,
--        encrypted or not. Only the "<algorithm> encryption service adapter"
--        row says NNE is in use, and its case differs on 11.2.0.2.0.
--        The view showed the account 1 SID on 23.26.2.0.0, 2 on 21.3, 19.3 and
--        12.2, 1 or 2 on 18.4, and 3 on 11.2.0.2.0, so a reader must filter on
--        its own SID
--   EN3  after the grant, the same rows. The grant changes nothing where PUBLIC
--        holds it
--
--   So a session can tell TLS from NETWORK_PROTOCOL, and NNE from its own
--   banner rows, with no grant on any release measured. The grant matters only
--   where a site has revoked PUBLIC's.
--
-- HOW TO RUN
--   Against the tier-1 stack, whose SYS and SYSTEM password is the public one
--   in test/compose.yaml:
--
--     MSYS_NO_PATHCONV=1 docker exec -i -e TNS_ADMIN=<dir> \
--       sopuli-test-oracle-free-1 sqlplus -S /nolog < 12_connection_encryption_probe.sql
--
--   <dir> is a directory in the container holding the client's sqlnet.ora:
--   SQLNET.ENCRYPTION_CLIENT = REQUIRED for NNE, or a WALLET_LOCATION that
--   trusts the server's certificate for TLS. For TLS, or against any other
--   database, copy the file, edit the two DEFINEs in the copy (a tcps:// dsn
--   for TLS), run the copy and delete it -- never substitute them with sed,
--   which puts the password in argv instead. /nolog, and every CONNECT made from
--   the script, so no password is ever in argv (invariant 1). Every CONNECT goes
--   through the listener, so each session is a network session.
--   MSYS_NO_PATHCONV is for Git Bash, which otherwise rewrites /nolog.
--
-- THROWAWAY DATABASES ONLY. Creates and drops one account, and grants it a
-- dictionary view as SYS.
--------------------------------------------------------------------------------
define dsn = //localhost:1521/FREEPDB1
define pwd = sopuli-test

WHENEVER SQLERROR CONTINUE
SET LINESIZE 200 PAGESIZE 100 FEEDBACK OFF VERIFY OFF HEADING ON
COLUMN banner FORMAT A100
COLUMN protocol FORMAT A10
COLUMN grantee FORMAT A24
COLUMN privilege FORMAT A10

CONNECT system/"&pwd"@&dsn

PROMPT
PROMPT == EN0: grants on SYS.V_$SESSION_CONNECT_INFO
SELECT grantee, privilege FROM dba_tab_privs
 WHERE table_name = 'V_$SESSION_CONNECT_INFO' ORDER BY grantee;

BEGIN EXECUTE IMMEDIATE 'DROP USER enc_probe CASCADE'; EXCEPTION WHEN OTHERS THEN NULL; END;
/
CREATE USER enc_probe IDENTIFIED BY "Enc_Probe_1";
GRANT CREATE SESSION TO enc_probe;

CONNECT enc_probe/"Enc_Probe_1"@&dsn

PROMPT
PROMPT == EN1: NETWORK_PROTOCOL, no grant
SELECT sys_context('userenv','network_protocol') AS protocol FROM dual;

PROMPT
PROMPT == EN2: V$SESSION_CONNECT_INFO, nothing granted to the account
SELECT network_service_banner AS banner
  FROM v$session_connect_info
 WHERE sid = sys_context('userenv','sid');
SELECT count(DISTINCT sid) AS sids_visible FROM v$session_connect_info;

CONNECT sys/"&pwd"@&dsn AS SYSDBA
GRANT SELECT ON sys.v_$session_connect_info TO enc_probe;

CONNECT enc_probe/"Enc_Probe_1"@&dsn

PROMPT
PROMPT == EN3: V$SESSION_CONNECT_INFO, granted
SELECT network_service_banner AS banner
  FROM v$session_connect_info
 WHERE sid = sys_context('userenv','sid');
SELECT count(DISTINCT sid) AS sids_visible FROM v$session_connect_info;

CONNECT system/"&pwd"@&dsn
DROP USER enc_probe CASCADE;
EXIT
