START TRANSACTION ;

alter table branch_enis alter column mac set not null;
alter table branch_enis alter column security_groups set not null;
ALTER TABLE branch_enis ADD constraint must_have_security_groups CHECK (security_groups != ARRAY[]::text[]);

COMMIT ;