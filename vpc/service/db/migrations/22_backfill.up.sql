INSERT INTO htb_classid(trunk_eni, class_id)
SELECT trunk_enis.id,
       series.class_id
FROM
    (SELECT id
     FROM trunk_enis) trunk_enis,
    (SELECT generate_series(10010, 15000) AS class_id) series ON CONFLICT DO NOTHING;