START TRANSACTION ;
alter table branch_eni_attachments
    add association_id text;

COMMIT;