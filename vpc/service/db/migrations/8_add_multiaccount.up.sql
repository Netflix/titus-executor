create table eni_permissions
(
    id bigserial not null
        constraint eni_permissions_pk
            primary key,
    branch_eni text
        constraint eni_permissions_branch_enis_branch_eni_fk
            references branch_enis
            on delete cascade,
    account_id text
);

create unique index eni_permissions_branch_eni_account_id_uindex
    on eni_permissions (branch_eni, account_id);

create table trunk_eni_accounts
(
    id bigserial
        constraint trunk_eni_accounts_pk
            primary key,
    account_id text,
    region text
);

create unique index trunk_eni_accounts_account_id_region_uindex
    on trunk_eni_accounts (account_id, region);

