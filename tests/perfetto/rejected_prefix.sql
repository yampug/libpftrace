SELECT CASE WHEN (SELECT count(*) FROM slice WHERE name IN ('good', 'okay')) = 2 THEN 'ok' ELSE 'fail' END;
SELECT CASE WHEN (SELECT count(*) FROM slice WHERE name = 'too_long') = 0 THEN 'ok' ELSE 'fail' END;
