# pihole00 IP configuration

## Purpose

This document records the NetworkManager configuration applied to `pihole00`
on July 26, 2026. The host is the backup Pi-hole and Unbound node in the
keepalived DNS cluster.

This change added a permanent IPv6 Unique Local Address (ULA) while preserving
the existing static IPv4 address and automatically assigned global IPv6
connectivity.

## Address plan

| Purpose | Address |
| --- | --- |
| Host IPv4 | `10.1.0.54/22` |
| IPv4 default gateway | `10.1.0.1` |
| Host IPv4 DNS resolver | `10.1.0.1` |
| Host IPv6 ULA | `fd36:5aa8:6971:1::54/64` |
| Global IPv6 | Assigned automatically by router advertisement |
| IPv6 default gateway | Learned automatically by router advertisement |
| Existing keepalived IPv4 VIP | `10.1.0.55` |
| Planned keepalived IPv6 VIP | `fd36:5aa8:6971:1::55` |

The permanent ULA is independent of the ISP-delegated global IPv6 prefix. The
host continues to receive a global IPv6 address automatically so that changes
to the ISP prefix do not require manual host reconfiguration.

## NetworkManager profile

| Property | Value |
| --- | --- |
| Connection | `Wired connection 1` |
| Interface | `eth0` |
| IPv4 method | `manual` |
| IPv6 method | `auto` |
| Autoconnect | `yes` |

`ipv6.method auto` is intentional. NetworkManager installs the static ULA from
the profile while continuing to accept the global IPv6 prefix, default route,
and DNS information advertised by the UDM-SE.

## Configuration procedure

### Record the original state

```bash
hostname
nmcli -t -f NAME,DEVICE connection show --active
ip -4 address show dev eth0
ip -6 address show dev eth0
ip -4 route
ip -6 route
```

Before the change, `pihole00` was confirmed to be the backup and did not own
the keepalived VIP:

```bash
ip -4 address show dev eth0 | grep '10.1.0.55' \
  || echo "VIP not present: correct"
```

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
  ipv4.addresses "10.1.0.54/22" \
  ipv4.gateway "10.1.0.1" \
  ipv4.dns "10.1.0.1" \
  ipv6.method auto \
  ipv6.addresses "fd36:5aa8:6971:1::54/64" \
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
print
quit
```

The verification result was:

```text
Verify connection: OK
```

### Activate the profile

Keepalived was stopped temporarily on the backup node before cycling the
connection:

```bash
sudo systemctl stop keepalived
sudo nmcli connection up "Wired connection 1"
```

Stopping keepalived prevented the backup from participating in a VRRP election
during the network interruption. The existing IPv4 address did not change, but
an SSH session could still be interrupted while NetworkManager reactivated the
profile.

## Validation results

### Addresses and routes

The active connection reported:

```text
GENERAL.STATE:      100 (connected)
GENERAL.CONNECTION: Wired connection 1
```

The validated addresses were:

```text
10.1.0.54/22
fd36:5aa8:6971:1::54/64
2600:1702:7370:2f4f:5d5:46f0:b951:319b/64
```

The ULA and IPv4 address reported infinite valid and preferred lifetimes. The
global IPv6 address remained dynamic, as intended.

The complete routing tables were inspected with:

```bash
ip -4 route
ip -6 route
```

The validated IPv4 routes were:

```text
default via 10.1.0.1 dev eth0 proto static metric 100
10.1.0.0/22 dev eth0 proto kernel scope link src 10.1.0.54 metric 100
```

This confirms that `10.1.0.0/22` is directly connected through `eth0` and that
traffic outside the LAN uses the static `10.1.0.1` gateway.

The validated IPv6 routes were:

```text
2600:1702:7370:2f4f::/64 dev eth0 proto ra metric 100 pref medium
fd36:5aa8:6971:1::/64 dev eth0 proto kernel metric 100 pref medium
fe80::/64 dev eth0 proto kernel metric 1024 pref medium
default via fe80::6ad7:9aff:fe1f:73d5 dev eth0 proto ra metric 100 pref high
```

This confirms that the ISP global prefix and default gateway are learned
through router advertisements, the permanent ULA is directly connected, and
the IPv6 link-local network is available on `eth0`.

IPv6 duplicate-address detection completed without a `dadfailed` or
`tentative` flag.

### Connectivity

The following tests completed with zero packet loss:

```bash
ping -c 3 10.1.0.1
ping -6 -c 3 2606:4700:4700::1111
```

These tests confirmed connectivity to the IPv4 gateway and the global IPv6
Internet.

### Direct DNS service

Pi-hole answered directly on both node addresses:

```bash
dig @10.1.0.54 example.com A
dig -6 @fd36:5aa8:6971:1::54 example.com AAAA
```

Both queries returned `NOERROR` with address records. This confirmed that
Pi-hole was listening and responding on the new ULA.

### Keepalived

Keepalived was returned to service after the network tests:

```bash
sudo systemctl start keepalived
systemctl is-active keepalived
systemctl show keepalived -p ActiveState -p SubState
```

The validated state was:

```text
active
ActiveState=active
SubState=running
```

`pihole00` remained the backup and did not own `10.1.0.55`. A DNS query through
the active IPv4 VIP also returned `NOERROR`:

```bash
dig @10.1.0.55 example.com A
```

## Rollback

If this host configuration must be rolled back, activate the cloned profile
from local console access:

```bash
sudo systemctl stop keepalived

sudo nmcli connection up \
  "Wired connection 1 before ULA" \
  ifname eth0

ip -4 address show dev eth0
sudo systemctl start keepalived
```

Confirm that `10.1.0.54/22` is restored and keepalived returns to the
`BACKUP` state.

## Remaining IPv6 HA work

The host configuration described here is complete. It does not complete the
network-wide IPv6 HA deployment. The UDM-SE ULA and router advertisement work
was subsequently completed and is recorded in
[UDM-SE IPv6 ULA configuration](udm-se-ipv6-ula-configuration.md).

The following work remains separate:

1. Add `fd36:5aa8:6971:1::55` as a keepalived IPv6 VIP.
2. Test IPv6 VIP failover and failback.
3. Advertise only the IPv6 VIP, not a node address, as the LAN IPv6 DNS server.

The completed primary-node configuration is recorded in
[pihole0 IP configuration](pihole0-ip-configuration.md).

Do not advertise `fd36:5aa8:6971:1::54` as the client DNS server. It is the
backup node address and does not move during failover.
