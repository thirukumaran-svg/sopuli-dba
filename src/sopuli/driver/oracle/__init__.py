"""The Oracle driver (P1, `02-oracle-privileges.md`).

This file does not import ``oracledb``. The modules that connect import it.
ADR-006 rule 1: a vendor client is imported inside its backend module, on first
use, so that a config naming a driver this machine has not installed is a
diagnosable condition rather than a traceback.

:mod:`sopuli.driver.oracle.statements` is the half of the driver that needs no
database at all: what the statement looks like, and when the tool refuses to
build one. It is tier 0 because invariants 13 and 14 are properties of *text*,
and because the measured reason for them is counter-intuitive enough that a test
is the only durable way to keep them (``04-testing.md`` §5).
"""
