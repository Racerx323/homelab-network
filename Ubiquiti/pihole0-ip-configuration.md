# pihole0 IP configuration

## Purpose

This document records the NetworkManager configuration applied to `pihole0` on
July 26, 2026. The host is the preferred primary Pi-hole and Unbound node in
the keepalived DNS cluster.

The change added a permanent IPv6 Unique Local Address (ULA) while preserving
the existing static IPv4 address, automatically assigned global IPv6
connectivity, and the existing IPv4 keepalived service.

## Address plan

| Purpose | Address |
| --- | --- |
| Host IPv4 | `10.1.0.53/22` |
| IPv4 default gateway | `10.1.0.1` |
| Host IPv4 DNS resolver | `10.1.0.1` |
| Host IPv6 ULA | `fd36:5aa8:6971:1::53/64` |
| Global IPv6 | Assigned automatically by router advertisement |
| IPv6 default gateway | Learned automatically by router advertisement |
| Existing keepalived IPv4 VIP | `10.1.0.55` |
| Planned keepalived IPv6 VIP | `fd36:5aa8:6971:1::55` |

The permanent ULA is independent of the ISP-delegated global IPv6 prefix. The
host continues to receive global IPv6 and an IPv6 default route automatically.

## NetworkManager profile

| Property | Value |
| --- | --- |
| Connection | `Wired connection 1` |
| Interface | `eth0` |
| IPv4 method | `manual` |
| IPv6 method | `auto` |
| Autoconnect | `yes` |

`ipv6.method auto` is intentional. NetworkManager installs the static ULA from
the profile while continuing to accept the global IPv6 prefix, ULA prefix,
default route, and DNS information advertised by the UDM-SE.

## Pre-change validation

The active connection and interface were identified with:

```bash
hostname
nmcli device status
nmcli -t -f NAME,DEVICE,TYPE connection show --active
```

The observed host, connection, and interface were:

```text
j1-svpihole0
Wired connection 1
eth0
```

The existing addresses and routes were recorded:

```bash
ip -4 -o address show dev eth0 scope global
ip -6 -o address show dev eth0 scope global
ip -4 route
ip -6 route
```

Before the change, `pihole0` owned the active IPv4 keepalived VIP:

```text
10.1.0.53/22
10.1.0.55/22
```

Keepalived was active and a query through the VIP returned `NOERROR`:

```bash
systemctl is-active keepalived
dig @10.1.0.55 example.com A
```

## Configuration procedure

### Back up the connection profile

```bash
sudo nmcli connection clone \
  "Wired connection 1" \
  "Wired connection 1 before ULA"

sudo nmcli connection modify \
  "Wired connection 1 before ULA" \
  connection.autoconnect no
```

### Modify the active profile

```bash
sudo nmcli connection modify "Wired connection 1" \
  connection.interface-name eth0 \
  ipv4.method manual \
  ipv4.addresses "10.1.0.53/22" \
  ipv4.gateway "10.1.0.1" \
  ipv4.dns "10.1.0.1" \
  ipv6.method auto \
  ipv6.addresses "fd36:5aa8:6971:1::53/64" \
  ipv6.gateway "" \
  ipv6.ignore-auto-routes no \
  ipv6.ignore-auto-dns no
```

### Validate the saved profile

Profile verification was performed in the interactive NetworkManager editor:

```bash
sudo nmcli connection edit "Wired connection 1"
```

At the `nmcli>` prompt:

```text
verify
print ipv4
print ipv6
quit
```

The verification result was:

```text
Verify connection: OK
```

### Move the VIP to pihole00

Because `pihole0` was the active primary, its keepalived service was stopped
before cycling the network connection:

```bash
sudo systemctl stop keepalived
systemctl is-active keepalived
```

The expected local state was `inactive`. On `pihole00`, the VIP and DNS service
were then validated:

```bash
ip -4 address show dev eth0 | grep '10.1.0.55'
dig @10.1.0.55 example.com A
```

`pihole00` acquired `10.1.0.55/22`, and the DNS query returned `NOERROR`. This
kept the shared DNS service available during the primary-node network change.

### Activate the profile

With keepalived still stopped on `pihole0`, the modified connection was
activated:

```bash
sudo nmcli connection up "Wired connection 1"
```

NetworkManager reported that the connection activated successfully. The
existing IPv4 address did not change, but an SSH session could still be
interrupted while NetworkManager reactivated the profile.

## Validation results

### Addresses

The active connection reported:

```text
GENERAL.STATE:      100 (connected)
GENERAL.CONNECTION: Wired connection 1
```

The validated addresses were:

```text
10.1.0.53/22
fd36:5aa8:6971:1::53/64
fd36:5aa8:6971:1:6b6c:2527:d9c0:3ba2/64
2600:1702:7370:2f4f:36be:ff6a:755:fee3/64
```

The IPv4 address and `::53` ULA reported infinite valid and preferred
lifetimes. The other ULA was assigned dynamically by SLAAC, and the global
IPv6 address remained dynamic. The additional SLAAC ULA is expected and does
not replace or interfere with the permanent server address.

IPv6 duplicate-address detection completed without a `dadfailed` or
`tentative` flag.

### Routes

The complete routing tables were inspected with:

```bash
ip -4 route
ip -6 route
```

The validated IPv4 routes were:

```text
default via 10.1.0.1 dev eth0 proto static metric 100
10.1.0.0/22 dev eth0 proto kernel scope link src 10.1.0.53 metric 100
```

The validated IPv6 routes were:

```text
2600:1702:7370:2f4f::/64 dev eth0 proto ra metric 100 pref medium
fd36:5aa8:6971:1::/64 dev eth0 proto ra metric 100 pref medium
fe80::/64 dev eth0 proto kernel metric 1024 pref medium
default via fe80::6ad7:9aff:fe1f:73d5 dev eth0 proto ra metric 100 pref high
```

These routes confirm that IPv4 uses the static UDM-SE gateway, the ISP global
and ULA IPv6 prefixes are learned through router advertisements, and the IPv6
default route uses the UDM-SE link-local address.

### Connectivity

The following tests completed with zero packet loss:

```bash
ping -c 3 10.1.0.1
ping -6 -c 3 fd36:5aa8:6971:1::1
ping -6 -c 3 2606:4700:4700::1111
```

These tests confirmed connectivity to the IPv4 gateway, the UDM-SE ULA, and
the global IPv6 Internet.

### Direct DNS service

Pi-hole answered directly on both permanent node addresses:

```bash
dig @10.1.0.53 example.com A
dig -6 @fd36:5aa8:6971:1::53 example.com AAAA
```

Both queries returned `NOERROR` with address records. The shared IPv4 VIP also
continued to answer through `pihole00` during the maintenance window:

```bash
dig @10.1.0.55 example.com A
```

### Keepalived failback

After all direct network and DNS tests passed, keepalived was started on
`pihole0`:

```bash
sudo systemctl start keepalived
sleep 5
systemctl is-active keepalived
ip -4 address show dev eth0 | grep '10.1.0.55'
dig @10.1.0.55 example.com A
```

The validated result was:

```text
active
10.1.0.55/22
```

The VIP DNS query returned `NOERROR`. On `pihole00`, the VIP was absent,
confirming that it returned to the backup role:

```text
PASS: pihole00 returned to backup
```

This completed a successful IPv4 VIP failover and failback during the network
change.

## Rollback

Before rolling back the primary, confirm that keepalived and direct DNS are
healthy on `pihole00`. Then stop keepalived on `pihole0` and confirm the IPv4
VIP moves to the backup:

```bash
sudo systemctl stop keepalived
dig @10.1.0.55 example.com A
```

From local console access on `pihole0`, activate the cloned profile:

```bash
sudo nmcli connection up \
  "Wired connection 1 before ULA" \
  ifname eth0

ip -4 address show dev eth0
```

After validating `10.1.0.53/22` and direct DNS, start keepalived and confirm
the preferred primary reclaims `10.1.0.55`:

```bash
sudo systemctl start keepalived
sleep 5
ip -4 address show dev eth0 | grep '10.1.0.55'
dig @10.1.0.55 example.com A
```

## Remaining IPv6 HA work

The node network configuration is complete. The following work remains:

1. Add `fd36:5aa8:6971:1::55` as a keepalived IPv6 VIP.
2. Test IPv6 VIP ownership, failover, and failback.
3. Advertise only the IPv6 VIP, not a node address, as the LAN IPv6 DNS server.
4. Verify that LAN clients receive and use the shared IPv6 DNS VIP.

Related records:

- [pihole00 IP configuration](pihole00-ip-configuration.md)
- [UDM-SE IPv6 ULA configuration](udm-se-ipv6-ula-configuration.md)
