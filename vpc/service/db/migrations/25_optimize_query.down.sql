START TRANSACTION;
DROP INDEX ip_last_used_v3_ip_address_uindex;
create unique index ip_last_used_v3_ip_address_uindex
    on ip_last_used_v3 (ip_address, vpc_id);
COMMIT;