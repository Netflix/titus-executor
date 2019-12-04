START TRANSACTION ;
alter table branch_eni_attachments drop column association_id;
COMMIT;

