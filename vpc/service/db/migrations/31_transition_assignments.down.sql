START TRANSACTION;
ALTER TABLE assignments DROP COLUMN is_transition_assignment;
COMMIT;