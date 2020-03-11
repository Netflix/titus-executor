START TRANSACTION ;

DROP TYPE IF EXISTS association_action;
DROP TYPE IF EXISTS action_state;
DROP TABLE IF EXISTS branch_eni_actions_associate;
DROP TABLE IF EXISTS branch_eni_actions_disassociate;
COMMIT;