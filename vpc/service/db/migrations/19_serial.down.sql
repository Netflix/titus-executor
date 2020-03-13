START TRANSACTION DEFERRABLE;
DROP INDEX IF EXISTS branch_eni_attachments_association_token_uindex;
DROP INDEX IF EXISTS branch_eni_attachments_disassociation_token_uindex;
DROP INDEX IF EXISTS branch_eni_attachments_branch_eni_trunk_eni_idx_uindex;
DROP INDEX IF EXISTS branch_eni_attachments_state_index;
DROP INDEX IF EXISTS branch_eni_attachments_branch_eni_state_index;

alter table branch_eni_attachments alter column created_at drop not null;
alter table branch_enis drop IF EXISTS dirty_security_groups;
alter table branch_eni_attachments
    drop IF EXISTS association_token;

alter table branch_eni_attachments
    drop IF EXISTS disassociation_token;

alter table branch_eni_attachments
    drop IF EXISTS attachment_created_by;

alter table branch_eni_attachments
    drop IF EXISTS attachment_created_at;

alter table branch_eni_attachments
    drop IF EXISTS attachment_completed_by;

alter table branch_eni_attachments
    drop IF EXISTS attachment_completed_at;

alter table branch_eni_attachments
    drop IF EXISTS unattachment_created_by;

alter table branch_eni_attachments
    drop IF EXISTS unattachment_created_at;

alter table branch_eni_attachments
    drop IF EXISTS unattachment_completed_by;

alter table branch_eni_attachments
    drop IF EXISTS unattachment_completed_at;

alter table branch_eni_attachments
    drop IF EXISTS state;

alter table branch_eni_attachments
    drop IF EXISTS force;

alter table branch_eni_attachments
    drop IF EXISTS error_code;

alter table branch_eni_attachments
    drop IF EXISTS error_message;

DROP INDEX IF EXISTS branch_eni_attachments_trunk_eni_idx_uindex;
create unique index branch_eni_attachments_trunk_eni_idx_uindex
    on branch_eni_attachments (trunk_eni, idx);

DROP INDEX IF EXISTS branch_eni_attachments_branch_eni_uindex;
create unique index branch_eni_attachments_branch_eni_uindex
    on branch_eni_attachments (branch_eni);

DROP INDEX IF EXISTS branch_enis_subnet_id_index;
DROP TYPE IF EXISTS attachment_state;

ALTER TABLE branch_eni_attachments DROP CONSTRAINT IF EXISTS branch_eni_attachments_branch_eni_check;
ALTER TABLE branch_eni_attachments DROP CONSTRAINT IF EXISTS  branch_eni_attachments_trunk_eni_check;
ALTER TABLE branch_eni_attachments DROP CONSTRAINT IF EXISTS  branch_eni_attachments_association_id_check;

ALTER TABLE branch_enis DROP CONSTRAINT IF EXISTS branch_enis_branch_eni_check;
ALTER TABLE branch_enis DROP CONSTRAINT IF EXISTS branch_enis_subnet_id_check;
ALTER TABLE branch_enis DROP CONSTRAINT IF EXISTS branch_enis_vpc_id_check;

ALTER TABLE trunk_enis DROP CONSTRAINT IF EXISTS branch_enis_branch_eni_check;
ALTER TABLE trunk_enis DROP CONSTRAINT IF EXISTS branch_enis_subnet_id_check;
ALTER TABLE trunk_enis DROP CONSTRAINT IF EXISTS branch_enis_vpc_id_check;

COMMIT;
