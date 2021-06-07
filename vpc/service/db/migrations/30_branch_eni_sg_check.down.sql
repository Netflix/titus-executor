
START TRANSACTION;

DROP TRIGGER sg_exists_on_update ON branch_enis ;
DROP TRIGGER sg_exists_on_insert ON branch_enis ;
DROP FUNCTION check_sg_exists;

DROP TRIGGER sg_change_on_update ON branch_enis;
DROP FUNCTION check_sg_modifications;

COMMIT ;