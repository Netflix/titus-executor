DROP INDEX branch_eni_attachments_association_id_uindex;
DROP TABLE assignments;

alter table subnets
    drop cidr;

alter table branch_enis
    drop mac;

alter table trunk_enis
    drop mac;

-- This isn't going to "fix" the branch_enis table.