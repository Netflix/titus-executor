create table elastic_ips
(
    id serial
        constraint elastic_ips_pk
            primary key,
    allocation_id text,
    account_id text,
    public_ip inet,
    region text,
    network_border_group text,
    tags jsonb
);

create unique index elastic_ips_allocation_id_uindex
    on elastic_ips (allocation_id);

create unique index elastic_ips_public_ip_uindex
    on elastic_ips (public_ip);

create table availability_zones
(
    id serial
        constraint availability_zones_pk
            primary key,
    account_id text,
    group_name text,
    network_border_group text,
    region text,
    zone_id text,
    zone_name text
);

create unique index availability_zones_account_id_zone_id_uindex
    on availability_zones (account_id, zone_id);

create unique index availability_zones_account_id_zone_name_uindex
    on availability_zones (account_id, zone_name);

create table elastic_ip_attachments
(
    id serial
        constraint elastic_ip_attachments_pk
            primary key,
    elastic_ip_allocation_id text
        constraint elastic_ip_attachments_elastic_ips_allocation_id_fk
            references elastic_ips (allocation_id)
            on delete cascade,
    assignment_id text
        constraint elastic_ip_attachments_assignments_assignment_id_fk
            references assignments (assignment_id)
            on delete cascade,
    association_id text

);

create unique index elastic_ip_attachments_assignment_id_uindex
    on elastic_ip_attachments (assignment_id);

create unique index elastic_ip_attachments_elastic_ip_uindex
    on elastic_ip_attachments (elastic_ip_allocation_id);

create unique index elastic_ip_attachments_association_id_uindex
    on elastic_ip_attachments (association_id);

create table ip_address_attachments
(
    id serial
        constraint ip_address_attachments_pk
            primary key,
    ip_address_uuid uuid
        constraint ip_address_attachments_ip_addresses_id_fk
            references ip_addresses
            on delete cascade,
    assignment_id text
        constraint ip_address_attachments_assignments_assignment_id_fk
            references assignments (assignment_id)
            on delete cascade
);

create unique index ip_address_attachments_assignment_id_uindex
    on ip_address_attachments (assignment_id);

create unique index ip_address_attachments_ip_address_uuid_uindex
    on ip_address_attachments (ip_address_uuid);

