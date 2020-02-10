DROP INDEX branch_eni_attachments_association_id_uindex;
DROP TABLE assignments;

alter table subnets
    drop cidr;

DROP TABLE ip_last_used_v3;

-- This isn't going to "fix" the branch_enis table.