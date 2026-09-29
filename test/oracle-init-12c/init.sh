#!/bin/bash
# sopuli-dba : one-time init for oracle-12c (#572) -- the password file, a USERS
# tablespace in the root, then oracle-init/01_test_profiles.sql in the PDB
#
# Run by hand, once, after the first start -- this image has no user-script hook:
#
#   docker exec sopuli-test-oracle-12c-1 \
#     bash /opt/sopuli/oracle-init-12c/init.sh
#
# The 19c images source setup scripts from /opt/oracle/scripts/setup after DBCA;
# the 2017 12.2 image predates that convention. Its dockerInit.sh runs setupDB.sh
# or startupDB.sh and then tails the alert log, and there is nothing to mount a
# script into. Overriding its command to add one would mean owning its startup
# sequence, which is more to get wrong than one documented docker exec.
#
# 1. THE PASSWORD FILE. The image creates it with `orapwd` in the 12.2 format,
#    which enforces complexity on the SYS password, and the stack's shared
#    `sopuli-test` has no digit: measured 2026-09-29, the first start logged
#    `OPW-00029: Password complexity failed for SYS user : Password must contain
#    at least 1 digit.` and `ERROR : config DB failed`, and left the database
#    OPEN with no password file -- so the healthcheck passed and every remote
#    `AS SYSDBA` (the suite's install-script module, the leak probe's position 2)
#    would have been refused. Format 12 has no complexity rule. The password is
#    the container's own DB_PASSWD, read on stdin, never argv. The file lives in
#    the /ORCL volume, so this survives a recreated container.
#
# 2. A USERS TABLESPACE IN CDB$ROOT. This image's root has none -- SYSTEM,
#    SYSAUX, SYSEXT, TEMP and UNDOTBS1 only, with SYSTEM as the default -- where
#    a DBCA-built CDB, 19.3's included, has one. 00_install.sql's COMMON mode
#    defaults its tablespace parameter to USERS, and measured 2026-09-29 the
#    suite's COMMON install failed `ORA-00959: tablespace 'USERS' does not
#    exist`. That is the image, not the release, so the image is made to match
#    the CDB an estate runs rather than the script being changed to suit it.
#
# 3. THE TEST PROFILES, inside the PDB, for the same reason as oracle-init-19c/:
#    this image keeps COMMON_USER_PREFIX at C##, so SOPULI_* cannot be a common
#    profile in the root, and the PDB is where the suite connects.
#
# Safe to run twice: orapwd is force=y, and the SQL file is continue-on-error and
# reports what exists in its section 6.
#
# Every step but the profiles file stops the script on failure -- set -e, and
# WHENEVER SQLERROR/OSERROR EXIT in each block -- because a half-initialised
# database is the thing this script exists to prevent. The profiles file keeps
# its own continue-on-error: it expects release-dependent failures (no
# SOPULI_ROLLOVER below 19.12) and reports them.
#
# The LAST thing it does is write $READY_MARKER, in the /ORCL volume, and the
# compose healthcheck requires that file. So `healthy` means "initialised", not
# merely "open": until this has run the container stays `starting` (and turns
# `unhealthy` once the start period is spent), and a container recreated on the
# kept volume is healthy without running it again.

set -e
source /home/oracle/.bashrc
READY_MARKER=/ORCL/.sopuli-init-12c-done

echo "$DB_PASSWD" | orapwd file="$ORACLE_HOME/dbs/orapw$ORACLE_SID" format=12 force=y
echo "password file written: $ORACLE_HOME/dbs/orapw$ORACLE_SID (format 12)"

sqlplus -s / as sysdba <<'SQL'
WHENEVER SQLERROR EXIT FAILURE
WHENEVER OSERROR EXIT FAILURE
SET SERVEROUTPUT ON
DECLARE
  l_cnt PLS_INTEGER;
BEGIN
  SELECT COUNT(*) INTO l_cnt FROM dba_tablespaces WHERE tablespace_name = 'USERS';
  IF l_cnt = 0 THEN
    EXECUTE IMMEDIATE q'[CREATE TABLESPACE users DATAFILE
      '/u02/app/oracle/oradata/ORCL/users01.dbf'
      SIZE 10M AUTOEXTEND ON NEXT 10M MAXSIZE UNLIMITED]';
    DBMS_OUTPUT.PUT_LINE('created tablespace USERS in CDB$ROOT');
  ELSE
    DBMS_OUTPUT.PUT_LINE('tablespace USERS already exists in CDB$ROOT');
  END IF;
END;
/
exit
SQL

sqlplus -s / as sysdba <<SQL
WHENEVER SQLERROR EXIT FAILURE
ALTER SESSION SET CONTAINER = ${DB_PDB:-ORCLPDB1};
WHENEVER SQLERROR CONTINUE
@/opt/sopuli/oracle-init/01_test_profiles.sql
exit
SQL

touch "$READY_MARKER"
echo "init complete: $READY_MARKER written, the healthcheck will now pass"
