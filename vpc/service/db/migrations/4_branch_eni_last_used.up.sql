create table branch_eni_last_used
(
    branch_eni text not null
        constraint branch_eni_last_used_pk
            primary key
        constraint branch_eni_last_used_branch_enis_branch_eni_fk
            references branch_enis
            on delete cascade,
    last_used timestamp
);

