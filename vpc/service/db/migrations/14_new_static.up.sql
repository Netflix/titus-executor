create table static_enis
(
    id serial
        constraint static_enis_pk
            primary key,
    eni_id text,
    subnet_id text
        constraint static_enis_subnets_subnet_id_fk
            references subnets (subnet_id)
            on delete restrict
);

create unique index static_enis_eni_id_uindex
    on static_enis (eni_id);

create unique index ip_addresses_ip_address_subnet_id_uindex
    on ip_addresses (ip_address, subnet_id);

drop index ip_addresses_ipaddress;