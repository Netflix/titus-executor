START TRANSACTION ;
CREATE OR REPLACE FUNCTION check_sg_exists() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    security_group_id text;
BEGIN
    FOREACH security_group_id IN ARRAY NEW.security_groups
        LOOP
            PERFORM id FROM security_groups WHERE group_id = security_group_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Cannot find security group %', security_group_id;
            end if;
        END LOOP;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER sg_exists_on_update AFTER UPDATE OF security_groups ON branch_enis DEFERRABLE
    FOR EACH ROW EXECUTE PROCEDURE check_sg_exists();

CREATE CONSTRAINT TRIGGER sg_exists_on_insert AFTER INSERT ON branch_enis DEFERRABLE
    FOR EACH ROW EXECUTE PROCEDURE check_sg_exists();


CREATE OR REPLACE FUNCTION check_sg_modifications() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    assignment_count int;
BEGIN
    SELECT COUNT(*) INTO assignment_count FROM assignments
        JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
    WHERE
          branch_eni = NEW.branch_eni;
    IF assignment_count > 0 THEN
        RAISE EXCEPTION 'Cannot change security groups on ENI %, because there are % assignments', NEW.branch_eni, assignment_count;
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER sg_change_on_update AFTER UPDATE OF security_groups ON branch_enis INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE PROCEDURE check_sg_modifications();

COMMIT;
