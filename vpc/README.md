The VPC driver requires you to have a system like systemd-networkd bring up your interfaces.

We use the following configs:

`/etc/systemd/network/10-ens3.network`:

```
[Match]
Name=ens3

[Network]
DHCP=ipv4
ConfigureWithoutCarrier=true


[DHCP]
RouteMetric=10
UseDomains=yes
```

`/etc/systemd/network/10-eth0.network`:

```
[Match]
Name=eth0



[Network]
DHCP=ipv4
ConfigureWithoutCarrier=true

[DHCP]
RouteMetric=10
UseDomains=yes
```


`/etc/systemd/network/20-else.network`:

```
[Match]
Name=*

[Network]
ConfigureWithoutCarrier=true
LinkLocalAddressing=ipv6
```

