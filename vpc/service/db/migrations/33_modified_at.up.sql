START TRANSACTION ;
ALTER TABLE branch_enis ADD COLUMN aws_security_groups_updated timestamp;
COMMIT;