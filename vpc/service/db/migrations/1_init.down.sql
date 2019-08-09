START TRANSACTION ;
DROP TABLE public.ip_addresses;
DROP TABLE public.trusted_public_keys;
DROP TYPE public.public_key_type;
COMMIT;