# j2-svpi4mf permanent ULA operation

## Status and scope

| Field | Value |
| --- | --- |
| Operation | `j2-svpi4mf-permanent-ula-v1` |
| State | Definition |
| Authorization ready | No |
| Target host | `j2-svpi4mf` |
| Management FQDN | `j2-svpi4mf.local.theama.co` |
| SSH endpoint | `ama@10.1.2.170` |
| Interface | `eth0` |
| Expected connection | `Wired connection 1` |
| Permanent ULA | `fd36:5aa8:6971:1::170/64` |

This document defines a pending host-network operation. It does not authorize
host contact or configuration changes. Record execution evidence and task
outcomes outside Git. Do not add status, evidence paths, timestamps, or resume
points to this document.

## Ownership

`homelab-network` owns the ULA allocation and the NetworkManager change. The
existing UniFi `Default LAN` advertises `fd36:5aa8:6971:1::/64` through Router
Advertisement and SLAAC.

The other repositories retain these boundaries:

- `homelab-server-configs` owns inventory facts and the Nautobot qualification
  gate.
- `homelab-dns` owns authoritative `AAAA` and `PTR` records.

This operation must not change UniFi DHCP, Router Advertisement, DNS, firewall,
or routing settings. It must not change the host's IPv4 configuration.

## Intended network state

The active NetworkManager profile must retain:

| Property | Required state |
| --- | --- |
| `connection.id` | `Wired connection 1` |
| `connection.interface-name` | `eth0` |
| `ipv4.method` | `auto` |
| IPv4 address | `10.1.2.170/22` from the UniFi fixed-address assignment |
| IPv4 gateway | `10.1.0.1` |
| `ipv6.method` | `auto` |
| `ipv6.addresses` | Includes `fd36:5aa8:6971:1::170/64` |
| IPv6 routes | Continue accepting Router Advertisement routes |
| Global IPv6 | Continue accepting the delegated global prefix |

The host may retain a SLAAC-generated address from the ULA prefix. That
dynamic address does not replace the permanent `::170` address.

## Authorization blockers

Clear each blocker before requesting live execution:

- checkpoint this definition at a reviewed source revision;
- repeat the read-only target and NetworkManager preflight;
- confirm that UniFi and the LAN do not assign or use `::170` elsewhere;
- confirm local-console recovery access;
- review the exact mutation and rollback commands; and
- authorize one bounded execution window.

## Read-only preflight

Run these commands under a separate read-only authorization:

```bash
hostnamectl --static
ip -4 -json address show dev eth0
ip -6 -json address show dev eth0
ip -4 -json route show table all
ip -6 -json route show table all
nmcli --terse --fields NAME,UUID,TYPE,DEVICE connection show --active
nmcli --fields connection.id,connection.uuid,connection.interface-name \
  connection show "Wired connection 1"
nmcli --fields ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns \
  connection show "Wired connection 1"
nmcli --fields ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.never-default,ipv6.ignore-auto-routes,ipv6.ignore-auto-dns \
  connection show "Wired connection 1"
nmcli connection show "Wired connection 1 before Nautobot ULA"
```

The final command must report that the backup profile does not exist. Stop if
the hostname, interface, connection, IPv4 address, gateway, or IPv6 method
differs from this definition. Stop if the permanent ULA already exists and
review whether the operation has become unnecessary.

The operator must also inspect the UniFi fixed-address registry and search the
LAN neighbor tables for `fd36:5aa8:6971:1::170`. A response or neighbor entry
from another device blocks the operation.

## Mutation definition

The live operation requires a separate authorization for these exact changes.
Use the active connection UUID captured during preflight if its connection ID
still equals `Wired connection 1` and its device still equals `eth0`.

Create a persistent rollback profile before changing the active profile:

```bash
sudo nmcli connection clone \
  "Wired connection 1" \
  "Wired connection 1 before Nautobot ULA"
sudo nmcli connection modify \
  "Wired connection 1 before Nautobot ULA" \
  connection.autoconnect no
```

Append the permanent ULA. Do not replace the existing IPv6 address list:

```bash
sudo nmcli connection modify \
  "Wired connection 1" \
  +ipv6.addresses "fd36:5aa8:6971:1::170/64"
```

Inspect and verify the saved profile before applying it:

```bash
nmcli --fields connection.id,connection.uuid,connection.interface-name,ipv4.method,ipv4.addresses,ipv4.gateway,ipv6.method,ipv6.addresses \
  connection show "Wired connection 1"
sudo nmcli connection edit "Wired connection 1"
```

At the `nmcli>` prompt, run:

```text
verify
print ipv4
print ipv6
quit
```

Apply the supported IP-address change without cycling the connection:

```bash
sudo nmcli device reapply eth0
```

Stop and roll back if NetworkManager rejects the reapply. Do not use
`nmcli connection up` over SSH without a new authorization and confirmed
local-console coverage because reactivation can interrupt management access.

## Acceptance

Accept the operation only when every check passes:

```bash
hostnamectl --static
ip -4 -o address show dev eth0 scope global
ip -6 -o address show dev eth0 scope global
ip -4 route
ip -6 route
nmcli --fields GENERAL.STATE,GENERAL.CONNECTION device show eth0
nmcli --fields ipv4.method,ipv4.addresses,ipv4.gateway,ipv6.method,ipv6.addresses \
  connection show "Wired connection 1"
ping -c 3 10.1.0.1
ping -6 -c 3 fd36:5aa8:6971:1::1
ping -6 -c 3 2606:4700:4700::1111
```

Required results:

- `j2-svpi4mf` retains `10.1.2.170/22` and its IPv4 default route;
- `fd36:5aa8:6971:1::170/64` appears on `eth0` with no `tentative` or
  `dadfailed` flag and with permanent preferred and valid lifetimes;
- the global IPv6 address and link-local default route remain present;
- the IPv4 gateway, ULA gateway, and global IPv6 test address respond;
- the active profile remains `Wired connection 1`; and
- a new SSH connection to `ama@10.1.2.170` succeeds before the operator closes
  the original session.

The Nautobot read-only qualification must then report
`expected_permanent_ula_present: true`. DNS validation remains separate until
`homelab-dns` defines and authorizes any `AAAA` or `PTR` change.

## Rollback

Remove only the address added by this operation:

```bash
sudo nmcli connection modify \
  "Wired connection 1" \
  -ipv6.addresses "fd36:5aa8:6971:1::170/64"
sudo nmcli device reapply eth0
```

Confirm that IPv4 management access, the global IPv6 address, and both default
routes remain healthy. Remove the backup profile only under a later cleanup
authorization.

If direct rollback fails, use local console access to activate the cloned
profile:

```bash
sudo nmcli connection up \
  "Wired connection 1 before Nautobot ULA" \
  ifname eth0
```

After recovery, retain the failed-operation evidence outside Git and stop for
manual review.

## Evidence contract

Capture preflight, mutation, acceptance, and rollback output in a protected,
size-bounded directory outside the repository. The sanitized manifest may
contain command exit states and input hashes. It must not contain credentials,
UniFi tokens, full environment dumps, or unrestricted system logs.
