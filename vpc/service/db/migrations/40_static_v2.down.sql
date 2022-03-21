START TRANSACTION ;
DROP INDEX ip_addresses_ipv6address_subnet_id_uindex;
ALTER TABLE ip_addresses drop column ipv6address;
ALTER TABLE ip_addresses drop column v4prefix;
ALTER TABLE ip_addresses drop column v6prefix;
ALTER TABLE ip_addresses drop column subnet_id_id;
COMMIT;