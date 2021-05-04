START TRANSACTION;
alter table assignments
    add jumbo bool default false not null;

alter table assignments
    add bandwidth bigint default 0 not null;

alter table assignments
    add ceil bigint default 0 not null;

COMMIT;