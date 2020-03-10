START TRANSACTION;
alter table long_lived_locks alter column held_until type timestamptz using held_until::timestamptz;
COMMIT;