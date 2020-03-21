alter table assignments
    drop if exists completed;
alter table branch_enis
    drop if exists mac;
alter table trunk_enis
    drop if exists mac;
DROP TABLE IF EXISTS htb_classid;
alter table trunk_enis
    drop if exists generation;
