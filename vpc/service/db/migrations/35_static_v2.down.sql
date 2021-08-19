START TRANSACTION ;
DROP TABLE subnet_cidr_reservations_v4;
DROP INDEX ip_addresses_ipv6address_subnet_id_uindex;
ALTER TABLE ip_addresses drop column ipv6address;
ALTER TABLE ip_addresses drop column v4prefix;
ALTER TABLE ip_addresses drop column v6prefix;

COMMIT;
