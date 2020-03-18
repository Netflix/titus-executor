START TRANSACTION;
CREATE TYPE test_work_state AS ENUM (
    'undone',
    'done'
    );

create table test_work
(
    id serial not null
        constraint test_work_pk
            primary key,
    input text,
    output text,
    state test_work_state default 'undone'
);

create unique index test_work_input_uindex
    on test_work (input);

COMMIT;