START TRANSACTION ;
alter table branch_enis
    drop last_used;
COMMIT ;