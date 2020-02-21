DROP TABLE static_enis;

create unique index ip_addresses_ipaddress
    on ip_addresses (ip_address);