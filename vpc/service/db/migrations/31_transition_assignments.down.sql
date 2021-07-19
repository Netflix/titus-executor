START TRANSACTION;
ALTER TABLE assignments DROP COLUMN is_transition_assignment;
ALTER TABLE assignments DROP COLUMN transition_assignment;
ALTER TABLE assignments DROP COLUMN transition_last_used;
COMMIT;