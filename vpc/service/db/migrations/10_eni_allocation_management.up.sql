create table trunk_enis
(
    id serial
        constraint trunk_enis_pk
            primary key,
    trunk_eni text,
    account_id text,
    created_at timestamp default CURRENT_TIMESTAMP,
    az text,
    subnet_id text,
    vpc_id text,
    region text
);

create unique index trunk_enis_trunk_eni_uindex
    on trunk_enis (trunk_eni);

