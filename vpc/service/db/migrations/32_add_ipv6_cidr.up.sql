START TRANSACTION ;
create type reservation_type as enum ('prefix', 'explicit');

create table subnet_cidr_reservations_v6
(
    reservation_id text
        constraint subnet_cidr_reservations_v6_pk
            primary key,
    subnet_id int,
    prefix cidr,
    type reservation_type not null,
    description text not null,
    constraint subnet_cidr_reservations_v6_subnets_subnet_id_id_fk
        foreign key (subnet_id) references subnets (id)
            on delete cascade
);

create table subnet_usable_prefix
(
    id bigserial
        constraint subnet_usable_prefix_pk
            primary key,
    subnet_id int
        constraint subnet_usable_prefix_subnets_id_fk
            references subnets
            on delete cascade,
    prefix cidr not null,
    last_assigned bigint default 1,
    branch_eni_id int
        constraint subnet_usable_prefix_branch_enis_id_fk
            references branch_enis (id)
            on delete set null
);

create unique index subnet_usable_prefix_subnet_id_prefix_uindex
    on subnet_usable_prefix (subnet_id, prefix);

create unique index subnet_usable_prefix_branch_eni_id_uindex
    on subnet_usable_prefix (branch_eni_id);

create unique index subnet_cidr_reservations_v6_subnet_id_prefix_uindex
    on subnet_cidr_reservations_v6 (subnet_id, prefix);

alter table subnets add column cidr6 cidr;

UPDATE long_lived_locks SET held_until = now() + INTERVAL '1' DAY, held_by = 'noone' WHERE lock_name LIKE 'gc_enis_%';

COMMIT;