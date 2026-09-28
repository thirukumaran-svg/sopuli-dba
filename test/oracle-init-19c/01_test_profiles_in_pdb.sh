#!/bin/bash
# sopuli-dba : run oracle-init/01_test_profiles.sql in the PDB, for oracle-19c (#548)
#
# Why a wrapper rather than mounting oracle-init/ directly, as every other Oracle
# service does: that file creates profiles named SOPULI_*, and runs in CDB$ROOT.
# Oracle's own 19c image keeps COMMON_USER_PREFIX at its default of C##, so a
# profile created in the root must be named C##something -- measured on 19.3.0.0.0,
# 2026-09-27, all four CREATE PROFILEs gave ORA-65140: invalid common profile name.
# The gvenzl images set the prefix to empty, which is why the file works there;
# the difference is the image, not the release.
#
# The prefix is left alone on purpose: C## is what a real estate runs with, and
# this is the one container in the stack that matches it. So the same file runs
# inside the PDB instead, where the profiles are local and SOPULI_* is legal --
# and that is where the suite connects anyway. Section 5's CONTAINER=ALL grant
# fails there and falls back to the plain grant, which is the one the PDB needs.
#
# Sourced, not executed, by the image's runUserScripts.sh: no `exit` here.
#
# Only the container switch stops on error. Without the PDB, the file would run
# in CDB$ROOT and fail every profile with ORA-65140 -- the thing this wrapper
# exists to avoid -- so it is better not to run it at all. The file itself stays
# continue-on-error, as it is everywhere: each section catches what a release
# rejects and reports it, and section 6 prints which profiles exist. Neither
# exit status reaches the healthcheck (checkDBStatus.sh asks the database), so
# the log line is the signal, not the code.

sqlplus -s / as sysdba <<SQL
WHENEVER SQLERROR EXIT FAILURE
ALTER SESSION SET CONTAINER = ${ORACLE_PDB:-ORCLPDB1};
WHENEVER SQLERROR CONTINUE
@/opt/sopuli/oracle-init/01_test_profiles.sql
exit
SQL
