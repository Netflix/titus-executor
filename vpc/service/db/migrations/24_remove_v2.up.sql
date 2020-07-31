START TRANSACTION ;

DROP TABLE IF EXISTS branch_eni_actions_associate_DEPRECATED;
DROP TABLE IF EXISTS branch_eni_actions_disassociate_DEPRECATED;
DROP TYPE IF EXISTS association_action;
DROP TYPE IF EXISTS action_state;

DROP TABLE IF EXISTS trunk_eni_accounts_DEPRECATED;

COMMIT;
