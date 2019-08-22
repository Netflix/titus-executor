START TRANSACTION ;
CREATE TYPE public.public_key_type AS ENUM (
    'ed25519'
    );

CREATE TABLE public.ip_addresses (
                                     id uuid NOT NULL,
                                     az text,
                                     region text,
                                     subnet_id text,
                                     account text,
                                     ip_address inet,
                                     home_eni text,
                                     host_public_key bytea,
                                     host_public_key_signature bytea,
                                     message bytea,
                                     message_signature bytea
);
CREATE UNIQUE INDEX ip_addresses_ipaddress ON public.ip_addresses USING btree (ip_address);

ALTER TABLE ONLY public.ip_addresses
    ADD CONSTRAINT ip_addresses_pkey PRIMARY KEY (id);


CREATE TABLE public.trusted_public_keys (
                                            key bytea NOT NULL,
                                            hostname text,
                                            created_at timestamp without time zone,
                                            keytype public.public_key_type
);


ALTER TABLE ONLY public.trusted_public_keys
    ADD CONSTRAINT trusted_public_keys_pkey PRIMARY KEY (key);

COMMIT;
