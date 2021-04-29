START TRANSACTION ;
create table security_groups
(
    id bigserial
        constraint security_groups_pk
            primary key,
    group_id varchar(127),
    group_name text,
    owner_id text,
    vpc_id varchar(127),
    region varchar(127),
    account varchar(127)
);

create unique index security_groups_group_id_uindex
    on security_groups (group_id);

create index security_groups_region_account_index
    on security_groups (region, account);


COMMIT;