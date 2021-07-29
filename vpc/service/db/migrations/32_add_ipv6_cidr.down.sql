START TRANSACTION ;
DROP TABLE subnet_cidr_reservations_v6;
DROP TABLE subnet_usable_prefix;
DROP TYPE reservation_type;
alter table subnets drop column cidr6;
COMMIT ;