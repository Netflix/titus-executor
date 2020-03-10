START TRANSACTION;
alter table long_lived_locks alter column held_until type timestamp using held_until::timestamp;
COMMIT;