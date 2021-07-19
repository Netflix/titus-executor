START TRANSACTION;
alter table assignments
    add is_transition_assignment bool default false not null;

alter table assignments
    add transition_assignment bigint;

-- This prevents GC of assignment, but if the association is deleted
-- from the branch_eni_attachments table it properly cascades and deletes
-- this row.
alter table assignments
    add constraint assignments_assignments_id_fk
        foreign key (transition_assignment) references assignments
            on delete restrict;

create unique index assignments_branch_eni_association_uindex
    on assignments (branch_eni_association) WHERE is_transition_assignment;

alter table assignments
    add transition_last_used timestamp;

COMMIT;