-- This is to optimize the query:
-- SELECT ip_address, last_seen FROM ip_last_used_v3 WHERE host(ip_address) = any($1) AND vpc_id = $2
-- As seen in assignArbitraryIPv4AddressV3

-- Old query plan:
--                                        QUERY PLAN
-- -----------------------------------------------------------------------------------------
--  Seq Scan on ip_last_used_v3  (cost=0.00..0.00 rows=1 width=15)
--    Filter: ((vpc_id = 'foo'::text) AND (host(ip_address) = ANY ('{100.1.2.3}'::text[])))
-- (2 rows)

-- New Query Plan:
--                                                 QUERY PLAN
-- -----------------------------------------------------------------------------------------------------------
--  Index Scan using ip_last_used_v3_ip_address_uindex2 on ip_last_used_v3  (cost=0.15..6.05 rows=1 width=15)
--    Index Cond: (vpc_id = 'foo'::text)
--    Filter: (host(ip_address) = ANY ('{100.1.2.3}'::text[]))
-- (3 rows)

START TRANSACTION;
DROP INDEX ip_last_used_v3_ip_address_uindex;
create unique index ip_last_used_v3_ip_address_uindex
    on ip_last_used_v3 (vpc_id, ip_address);
COMMIT;