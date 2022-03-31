START TRANSACTION ;

alter table ip_addresses add column subnet_id_id int;
update ip_addresses
set subnet_id_id = subnets.id
from subnets
where subnets.subnet_id = ip_addresses.subnet_id;

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

alter table ip_addresses
    add constraint ip_addresees_subnets_subnet_id_id_id_fk
        foreign key (subnet_id_id) references subnets (id)
            on delete set null;

COMMIT;