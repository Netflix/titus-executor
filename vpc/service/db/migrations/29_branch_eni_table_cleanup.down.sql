START TRANSACTION ;

alter table branch_enis alter column mac drop not null;
alter table branch_enis alter column security_groups drop not null;
ALTER TABLE branch_enis DROP constraint must_have_security_groups;

COMMIT ;