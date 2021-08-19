START TRANSACTION ;
create table subnet_cidr_reservations_v4
(
    reservation_id text not null
        constraint subnet_cidr_reservations_v4_pk
            primary key,
    subnet_id integer
        constraint subnet_cidr_reservations_v4_subnets_subnet_id_id_fk
            references subnets
            on delete cascade,
    prefix cidr,
    type reservation_type not null,
    description text not null
);

create unique index subnet_cidr_reservations_v4_subnet_id_prefix_uindex
    on subnet_cidr_reservations_v4 (subnet_id, prefix);

alter table ip_addresses
    add ipv6address inet;

alter table ip_addresses
    add v6prefix text;

alter table ip_addresses
    add v4prefix text;

create unique index ip_addresses_ipv6address_subnet_id_uindex
    on ip_addresses (ipv6address, subnet_id);

alter table ip_addresses
    add constraint ip_addresses_subnet_cidr_reservations_v4_reservation_id_fk
        foreign key (v4prefix) references subnet_cidr_reservations_v4
            on delete set null;

alter table ip_addresses
    add constraint ip_addresses_subnet_cidr_reservations_v6_reservation_id_fk
        foreign key (v6prefix) references subnet_cidr_reservations_v6
            on delete set null;


COMMIT;
