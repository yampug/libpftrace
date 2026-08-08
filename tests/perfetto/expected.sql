-- One stable semantic assertion per result set. `run.sh` requires every row
-- to equal ok; a missing table row or changed decoded value returns fail.
SELECT CASE WHEN (SELECT count(*) FROM process WHERE name = 'compat-process' AND pid = 123) = 1 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM thread WHERE name = 'compat-thread' AND tid = 456) = 1 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM slice WHERE name = 'direct_begin') = 1 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM slice WHERE name IN ('direct_equivalent', 'builder_equivalent')) = 2 AND (SELECT min(ts) FROM slice WHERE name IN ('direct_equivalent', 'builder_equivalent')) = 1500 AND (SELECT max(ts) FROM slice WHERE name IN ('direct_equivalent', 'builder_equivalent')) = 1500 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM counter WHERE value = -9223372036854775808) = 1 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM args WHERE key IN ('string', 'int_min', 'int_max', 'uint_max', 'double', 'bool', 'pointer', 'builder_arg')) = 8 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM flow WHERE slice_out IN (SELECT id FROM slice WHERE name = 'direct_begin') AND slice_in IN (SELECT id FROM slice WHERE name = 'direct_end')) = 2 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM slice WHERE name = 'direct_instant') = 1 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM clock_snapshot WHERE clock_id IN (6, 64)) = 2 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM slice WHERE name IN ('good', 'okay')) = 2 AND (SELECT count(*) FROM slice WHERE name = 'too_long') = 0 THEN 'ok' ELSE 'fail' END;
