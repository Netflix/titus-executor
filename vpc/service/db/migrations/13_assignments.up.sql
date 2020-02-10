create unique index branch_eni_attachments_association_id_uindex
    on branch_eni_attachments (association_id);

alter table subnets
    add cidr cidr;

create table assignments
(
    id bigserial
        constraint assignments_pk
            primary key,
    branch_eni_association text
        constraint assignments_branch_eni_attachments_association_id_fk
            references branch_eni_attachments (association_id)
            on delete cascade,
    assignment_id text not null,
    ipv4addr inet,
    ipv6addr inet,
    created_at timestamp default CURRENT_TIMESTAMP
);

create unique index assignments_allocation_id_uindex
    on assignments (assignment_id);

create unique index assignments_branch_eni_association_ipv4addr_uindex
    on assignments (branch_eni_association, ipv4addr);

create unique index assignments_branch_eni_association_ipv6addr_uindex
    on assignments (branch_eni_association, ipv6addr);

create index assignments_branch_eni_association_index
    on assignments (branch_eni_association);

create unlogged table ip_last_used_v3
(
    id bigserial
        constraint ip_last_used_v3_pk
            primary key,
    ip_address inet not null,
    vpc_id text not null,
    last_seen timestamp not null
);

create unique index ip_last_used_v3_ip_address_uindex
    on ip_last_used_v3 (ip_address, vpc_id);

