create table warm_pool_override
(
    subnet_id varchar
        constraint warm_pool_override_pk
            primary key
        constraint warm_pool_override_subnets_subnet_id_fk
            references subnets (subnet_id)
            on update restrict on delete cascade,
    warm_pool_size int
);

