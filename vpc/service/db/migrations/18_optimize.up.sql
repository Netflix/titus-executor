START TRANSACTION ;
create unique index branch_eni_actions_associate_branch_eni_trunk_eni_idx_uindex
    on branch_eni_actions_associate (branch_eni, trunk_eni, idx) where state = 'pending';
COMMIT;
