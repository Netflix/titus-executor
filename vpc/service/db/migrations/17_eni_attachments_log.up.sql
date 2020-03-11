START TRANSACTION;

CREATE TYPE association_action AS ENUM (
    'associate',
    'disassociate'
    );


CREATE TYPE action_state AS ENUM (
    'pending',
    'failed',
    'completed'
    );

create table branch_eni_actions
(
    id bigserial
        constraint branch_eni_actions_pk
            primary key,

    token text,
    association_id text,
    branch_eni text not null
        constraint branch_eni_actions_branch_enis_branch_eni_fk
            references branch_enis
            on delete cascade,
    trunk_eni text not null
        constraint branch_eni_actions_trunk_enis_trunk_eni_fk
            references trunk_enis (trunk_eni)
            on delete cascade,
    idx int,
    action association_action not null,
    state action_state default 'pending' not null,
    created_at timestamp default now(),
    completed_at timestamp,
    created_by text,
    completed_by text,
    error_code text,
    error_message text
);

-- Although you should never have to disassociate two ENIs from the same trunk ENI, there's nothing
-- explicitly from preventing us from doing so
create unique index branch_eni_actions_trunk_eni_idx_uindex
    on branch_eni_actions (trunk_eni, idx) where state = 'pending' and action = 'associate';

create unique index branch_eni_actions_branch_eni_uindex
    on branch_eni_actions (branch_eni) where state = 'pending';

create unique index branch_eni_actions_token_uindex
    on branch_eni_actions (token);

COMMIT;