START TRANSACTION;
ALTER TABLE ip_last_used SET LOGGED;
ALTER TABLE branch_eni_last_used SET LOGGED;
COMMIT;