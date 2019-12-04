START TRANSACTION ;
DROP INDEX branch_eni_attachments_trunk_eni_idx_uindex;

create unique index branch_eni_attachments_trunk_eni_idx_uindex
    ON branch_eni_attachments (trunk_eni, idx)
    WHERE state = 'attached';
COMMIT;