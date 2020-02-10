DROP TABLE assignments;

DROP INDEX branch_eni_attachments_association_id_uindex;

alter table subnets
    drop cidr;

DROP TABLE ip_last_used_v3;

alter table branch_eni_attachments
    drop attachment_generation;

alter table branch_enis
    drop last_assigned_to;

DROP TABLE long_lived_locks;

-- This isn't going to "fix" the branch_enis table.