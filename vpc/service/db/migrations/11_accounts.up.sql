create table accounts
(
    id serial
        constraint accounts_pk
            primary key,
    account_id text,
    region text
);

create unique index accounts_account_id_region_uindex
    on accounts (account_id, region);

INSERT INTO accounts(region, account_id)
SELECT (regexp_match(availability_zone, '[a-z]+-[a-z]+-[0-9]+'))[1] AS region, account
FROM account_mapping
GROUP BY region, account;

create table subnets
(
    id serial
        constraint subnets_pk
            primary key,
    az text,
    az_id text,
    vpc_id text,
    account_id text,
    subnet_id text
);

create unique index subnets_subnet_id_uindex
    on subnets (subnet_id);

alter table branch_enis
    add security_groups text array;

alter table branch_enis
    add modified_at timestamp;

UPDATE branch_enis SET modified_at = created_at WHERE modified_at IS NULL;

create index branch_eni_attachments_trunk_eni_index
    on branch_eni_attachments (trunk_eni);

alter table branch_eni_attachments
    add created_at timestamp default CURRENT_TIMESTAMP;