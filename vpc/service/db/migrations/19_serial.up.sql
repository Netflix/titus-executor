START TRANSACTION;
CREATE TYPE attachment_state AS ENUM (
    'attaching',
    'attached',
    'unattaching',
    'unattached',
    'failed'
    );

UPDATE branch_eni_attachments SET created_at = now() WHERE created_at IS NULL;
alter table branch_eni_attachments alter column created_at set not null;
alter table branch_enis
    add dirty_security_groups bool default false;
alter table branch_eni_attachments
    add association_token text;

alter table branch_eni_attachments
    add disassociation_token text;

alter table branch_eni_attachments
    add attachment_created_by text;

alter table branch_eni_attachments
    add attachment_created_at timestamp default now();

alter table branch_eni_attachments
    add attachment_completed_by text;

alter table branch_eni_attachments
    add attachment_completed_at timestamp;

alter table branch_eni_attachments
    add unattachment_created_by text;

alter table branch_eni_attachments
    add unattachment_created_at timestamp;

alter table branch_eni_attachments
    add unattachment_completed_by text;

alter table branch_eni_attachments
    add unattachment_completed_at timestamp;

alter table branch_eni_attachments
    add state attachment_state default 'attached';

alter table branch_eni_attachments
    add force bool default false;

alter table branch_eni_attachments
    add error_code text;

alter table branch_eni_attachments
    add error_message text;

create unique index branch_eni_attachments_association_token_uindex
    on branch_eni_attachments (association_token);

create unique index branch_eni_attachments_disassociation_token_uindex
    on branch_eni_attachments (disassociation_token);

DROP INDEX IF EXISTS branch_eni_attachments_branch_eni_uindex;
DROP INDEX IF EXISTS branch_eni_attachments_trunk_eni_idx_uindex;
DROP INDEX IF EXISTS branch_eni_attachments_branch_eni_trunk_eni_idx_uindex;

create unique index branch_eni_attachments_branch_eni_trunk_eni_idx_uindex
    on branch_eni_attachments (branch_eni, trunk_eni, idx) where state = 'attaching' OR state = 'attached' OR state = 'unattaching';

create unique index branch_eni_attachments_trunk_eni_idx_uindex
    on branch_eni_attachments (trunk_eni, idx) where state = 'attaching' OR state = 'attached' OR state = 'unattaching';

create unique index branch_eni_attachments_branch_eni_uindex
    on branch_eni_attachments (branch_eni) where  state = 'attaching' OR state = 'attached' OR state = 'unattaching';

create index branch_eni_attachments_state_index
    on branch_eni_attachments (state);

create index branch_enis_subnet_id_index
    on branch_enis (subnet_id);

create index branch_eni_attachments_branch_eni_state_index
    on branch_eni_attachments (branch_eni, state);

alter table branch_eni_attachments alter column state set not null;

UPDATE branch_eni_attachments SET state = 'attached';

ALTER TABLE branch_eni_attachments ADD CONSTRAINT branch_eni_attachments_branch_eni_check CHECK(branch_eni LIKE 'eni-%');
ALTER TABLE branch_eni_attachments ADD CONSTRAINT branch_eni_attachments_trunk_eni_check CHECK(trunk_eni LIKE 'eni-%');
ALTER TABLE branch_eni_attachments ADD CONSTRAINT branch_eni_attachments_association_id_check CHECK(association_id IS NULL OR association_id LIKE 'trunk-assoc-%');

ALTER TABLE branch_enis ADD CONSTRAINT branch_enis_branch_eni_check CHECK(branch_eni LIKE 'eni-%');
ALTER TABLE branch_enis ADD CONSTRAINT branch_enis_subnet_id_check CHECK(subnet_id LIKE 'subnet-%');
ALTER TABLE branch_enis ADD CONSTRAINT branch_enis_vpc_id_check CHECK(vpc_id LIKE 'vpc-%');

ALTER TABLE trunk_enis ADD CONSTRAINT branch_enis_branch_eni_check CHECK(trunk_eni LIKE 'eni-%');
ALTER TABLE trunk_enis ADD CONSTRAINT branch_enis_subnet_id_check CHECK(subnet_id LIKE 'subnet-%');
ALTER TABLE trunk_enis ADD CONSTRAINT branch_enis_vpc_id_check CHECK(vpc_id LIKE 'vpc-%');

alter table branch_eni_attachments alter column state set not null;

COMMIT;
