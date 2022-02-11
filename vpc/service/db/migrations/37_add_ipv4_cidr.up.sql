START TRANSACTION ;

create table subnet_cidr_reservations_v4
(
    reservation_id text
        constraint subnet_cidr_reservations_v4_pk
            primary key,
    subnet_id int,
    prefix cidr,
    type reservation_type not null,
    description text not null,
    constraint subnet_cidr_reservations_v4_subnets_subnet_id_id_fk
        foreign key (subnet_id) references subnets (id)
            on delete cascade
);

create unique index subnet_cidr_reservations_v4_subnet_id_prefix_uindex
    on subnet_cidr_reservations_v4 (subnet_id, prefix);

COMMIT;