START TRANSACTION ;

create type branch_eni_state as enum ('unknown', 'attached', 'unattached');

create table scheduled_tasks
(
    id serial not null
        constraint scheduled_tasks_pk
            primary key,
    name text not null,
    last_run timestamp default CURRENT_TIMESTAMP
);

create unique index scheduled_tasks_name_uindex
    on scheduled_tasks (name);

create table ip_last_used
(
    ip_address inet not null
        constraint ip_last_used_pk
            primary key,
    last_used timestamp,
    last_allocated timestamp,
    id serial not null
);

create unique index ip_last_used_id_uindex
    on ip_last_used (id);

create table branch_enis
(
    branch_eni text not null
        constraint branch_enis_pkey
            primary key,
    created_at timestamp default CURRENT_TIMESTAMP,
    account_id text not null,
    subnet_id text,
    id serial not null,
    az text,
    vpc_id text
);

create unique index branch_enis_id_uindex
    on branch_enis (id);

create table branch_eni_attachments
(
    id serial not null
        constraint branch_eni_attachments_pk
            primary key,
    branch_eni text not null
        constraint branch_eni_attachments_branch_enis_branch_eni_fk
            references branch_enis
            on delete cascade,
    state branch_eni_state default 'unknown'::branch_eni_state not null,
    trunk_eni text,
    idx integer
);

create unique index branch_eni_attachments_branch_eni_uindex
    on branch_eni_attachments (branch_eni);

create unique index branch_eni_attachments_trunk_eni_idx_uindex
    on branch_eni_attachments (trunk_eni, idx);

create table account_mapping
(
    id serial not null
        constraint account_mapping_pk
            primary key,
    account text not null,
    availability_zone text not null,
    vpc_id text not null,
    subnet_id text not null
);

create unique index account_mapping_account_availability_zone_uindex
    on account_mapping (account, availability_zone);


COMMIT;