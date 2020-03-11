START TRANSACTION;

CREATE TYPE action_state AS ENUM (
    'pending',
    'failed',
    'completed'
    );

create table branch_eni_actions_associate
(
    id bigserial
        constraint branch_eni_actions_associate_pk
            primary key,
    token text not null,
    association_id text,
    branch_eni text not null
        constraint branch_eni_actions_associate_branch_enis_branch_eni_fk
            references branch_enis
            on delete cascade,
    trunk_eni text not null
        constraint branch_eni_actions_associate_trunk_enis_trunk_eni_fk
            references trunk_enis (trunk_eni)
            on delete cascade,
    idx int not null,
    state action_state default 'pending' not null,
    created_at timestamp default now(),
    created_by text,
    completed_at timestamp,
    completed_by text,
    error_code text,
    error_message text
);

create unique index branch_eni_actions_associate_branch_eni_uindex
    on branch_eni_actions_associate (branch_eni) where state = 'pending';

create unique index branch_eni_actions_associate_token_uindex
    on branch_eni_actions_associate (token);

create unique index branch_eni_actions_associate_trunk_eni_idx_uindex
    on branch_eni_actions_associate (trunk_eni, idx)  where state = 'pending';

create table branch_eni_actions_disassociate
(
    id bigserial
        constraint branch_eni_actions_disassociate_pk
            primary key,
    token text not null,
    association_id text not null
        constraint bea_disassociate_branch_eni_attachments_association_id_fk
            references branch_eni_attachments (association_id)
            on delete cascade,
    state action_state default 'pending' not null,
    created_at timestamp default now(),
    created_by text,
    completed_at timestamp,
    completed_by text,
    error_code text,
    error_message text
);

create unique index branch_eni_actions_disassociate_association_id_uindex
    on branch_eni_actions_disassociate (association_id) where state = 'pending';

create unique index branch_eni_actions_disassociate_token_uindex
    on branch_eni_actions_disassociate (token);

COMMIT;