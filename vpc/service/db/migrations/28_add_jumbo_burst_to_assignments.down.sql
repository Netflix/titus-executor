START TRANSACTION ;
alter table assignments drop column bandwidth;
alter table assignments drop column ceil;
alter table assignments drop column jumbo;
COMMIT;
