START TRANSACTION;
DROP TABLE scheduled_tasks;
DROP TABLE ip_last_used;
DROP TABLE IF EXISTS branch_eni_attachments CASCADE ;
DROP TABLE IF EXISTS branch_enis CASCADE ;
DROP TABLE account_mapping;
DROP TYPE branch_eni_state;

COMMIT;