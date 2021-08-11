START TRANSACTION;
ALTER TABLE branch_enis DROP COLUMN aws_security_groups_updated;
COMMIT;
