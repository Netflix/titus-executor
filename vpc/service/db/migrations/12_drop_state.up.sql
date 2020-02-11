START TRANSACTION ;
DROP INDEX branch_eni_attachments_trunk_eni_idx_uindex;
alter table branch_eni_attachments drop column state;
DROP TYPE branch_eni_state;
create unique index branch_eni_attachments_trunk_eni_idx_uindex on branch_eni_attachments (trunk_eni, idx);
COMMIT;