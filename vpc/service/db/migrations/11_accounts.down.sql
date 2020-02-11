DROP TABLE accounts;
DROP TABLE subnets;

alter table branch_enis
    DROP security_groups;

alter table branch_enis
    DROP modified_at;

alter table branch_eni_attachments
    DROP created_at;

DROP INDEX known_branch_eni_attachments_trunk_eni_index;