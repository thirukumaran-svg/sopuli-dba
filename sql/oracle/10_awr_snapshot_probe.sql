--------------------------------------------------------------------------------
-- sopuli-dba : does a leaked statement reach AWR?   (v1)
--
-- STATUS: run on 19c EE 19.32.0.0.0 (an OCI Base Database Service DB system,
-- CONTROL_MANAGEMENT_PACK_ACCESS = DIAGNOSTIC+TUNING) on 2026-10-01 (#581),
-- once, straight after a 02_password_leak_probe.sql position-1 run. C3 reached
-- DBA_HIST_SQLTEXT and AWR_ROOT_SQLTEXT from the uncoloured snapshot; C1, C2
-- and C4 reached neither, uncoloured or after C3 was coloured. Untried on every
-- other release: none of the container images has the Diagnostics Pack, and
-- 11.2 -- where the plain ALTER USER IS retained (#387) -- is the case this
-- cannot yet answer.
--
-- The WHENEVER SQLERROR line and the uncolour-on-failure handler came from
-- review after that run, and are UNRUN: the node was stopped. The first run
-- to use them should note it here.
--
-- The question 02's sweep leaves open (ddl-text-awr in docs/README.md): its
-- DBA_HIST_SQLTEXT row reads before any snapshot exists, so it can only ever
-- say pop=n. This takes the snapshot and sweeps again.
--
-- HOW TO RUN
--   In CDB$ROOT, as SYSDBA, IMMEDIATELY after 02_password_leak_probe.sql has
--   planted its canaries -- the cursors must still be in the shared pool:
--
--     sqlplus -s / as sysdba @10_awr_snapshot_probe.sql
--
--   Needs the Diagnostics Pack. Without it the snapshot calls succeed and
--   capture nothing, which reads as clean and is not.
--
-- TWO SNAPSHOTS, TWO QUESTIONS. The first is uncoloured: does the leak reach
-- AWR on its own? AWR keeps only each snapshot's top SQL, so on a quiet
-- database almost anything ranks, and on a busy one it might not -- a capture
-- here is "it can and did", and a miss would be "not this time", never "safe".
-- The second colours every cursor holding C3 (DBMS_WORKLOAD_REPOSITORY.
-- ADD_COLORED_SQL), which forces capture whatever its rank: can it reach AWR
-- at all? The colouring is removed again at the end.
--
-- CANARIES ARE ASSEMBLED FROM PIECES, as in 02 §4b: no statement here contains
-- one whole, so this script's own text can never be the finding -- and its own
-- cursors are AWR candidates too.
--
-- THROWAWAY DATABASES ONLY. A captured canary stays in AWR for the retention
-- period (8 days on the DB system); DBMS_WORKLOAD_REPOSITORY.DROP_SNAPSHOT_RANGE
-- removes it before then.
--------------------------------------------------------------------------------
set serveroutput on size unlimited lines 200 pages 100 feed off
-- Fatal from here on: nothing below is expected to fail, and a run that
-- carried on past a failed snapshot would still reach EXIT with status 0 and
-- read as a measurement it never made.
whenever sqlerror exit sql.sqlcode
col name format a40
col value format a30
prompt === preconditions
select name, value from v$parameter
 where name in ('control_management_pack_access','statistics_level','awr_pdb_autoflush_enabled');
select con_id, name from v$containers order by con_id;

declare
  type t_list is table of varchar2(40);
  c_pfx  constant varchar2(20) := 'S0puli' || 'Canary';
  v_sfx  t_list := t_list('1Aq7x#_', '2Bq7x#_', '3Cq7x#_', '4Dq7x#_');
  l_ids  t_list := t_list();

  procedure sweep(p_label varchar2) is
    l_n  pls_integer;
    l_c  varchar2(30);
  begin
    dbms_output.put_line('--- ' || p_label);
    for i in 1 .. v_sfx.count loop
      l_c := c_pfx || v_sfx(i);
      select count(*) into l_n from v$sql where instr(sql_fulltext, l_c) > 0;
      dbms_output.put_line(rpad('  C' || i || ' in V$SQL (all containers)', 46) || l_n);
      select count(*) into l_n from dba_hist_sqltext where instr(sql_text, l_c) > 0;
      dbms_output.put_line(rpad('  C' || i || ' in DBA_HIST_SQLTEXT', 46) || l_n);
      select count(*) into l_n from awr_root_sqltext where instr(sql_text, l_c) > 0;
      dbms_output.put_line(rpad('  C' || i || ' in AWR_ROOT_SQLTEXT', 46) || l_n);
    end loop;
  end;

  procedure snap(p_label varchar2) is
    l_id number;
  begin
    l_id := dbms_workload_repository.create_snapshot('ALL');
    dbms_output.put_line(p_label || ': snapshot ' || l_id || ' taken (flush level ALL)');
  end;

begin
  sweep('before any snapshot');
  snap('uncoloured');
  sweep('after the uncoloured snapshot -- does the leak reach AWR by itself?');

  -- Colour every cursor that holds C3, so the next snapshot must capture it
  -- whatever its rank. That answers "can it reach AWR", not "does it".
  for r in (select distinct sql_id from v$sql
             where instr(sql_fulltext, c_pfx || v_sfx(3)) > 0) loop
    dbms_workload_repository.add_colored_sql(sql_id => r.sql_id);
    l_ids.extend; l_ids(l_ids.count) := r.sql_id;
    dbms_output.put_line('coloured ' || r.sql_id);
  end loop;
  if l_ids.count = 0 then
    dbms_output.put_line('no cursor holds C3 any more -- the coloured half cannot be run');
  else
    begin
      snap('coloured');
      sweep('after the coloured snapshot -- can it reach AWR?');
    exception when others then
      -- Never leave a cursor coloured behind a failure: every later snapshot
      -- would capture it. Uncolour, then let the error stop the script.
      for i in 1 .. l_ids.count loop
        dbms_workload_repository.remove_colored_sql(sql_id => l_ids(i));
      end loop;
      raise;
    end;
    for i in 1 .. l_ids.count loop
      dbms_workload_repository.remove_colored_sql(sql_id => l_ids(i));
    end loop;
    dbms_output.put_line('colouring removed');
  end if;
end;
/
exit
