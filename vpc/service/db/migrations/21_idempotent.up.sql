alter table assignments
    add completed bool default false not null;
alter table branch_enis
    add mac macaddr;
alter table trunk_enis
    add mac macaddr;

alter table trunk_enis
    add generation int;

START TRANSACTION;
create table htb_classid
(
    id bigserial
        constraint htb_classid_pk
            primary key,
    trunk_eni int not null
        constraint htb_classid_trunk_enis_id_fk
            references trunk_enis
            on delete cascade,
    assignment_id bigint
        constraint htb_classid_assignments_id_fk
            references assignments (id)
            on delete set null,
    class_id int
);

create unique index htb_classid_assignment_id_uindex
    on htb_classid (assignment_id);

create unique index htb_classid_trunk_eni_class_id_uindex
    on htb_classid (trunk_eni, class_id);

create index htb_classid_trunk_eni_index
    on htb_classid (trunk_eni);

COMMIT;