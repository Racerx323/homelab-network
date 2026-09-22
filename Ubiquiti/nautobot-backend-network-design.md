# Nautobot backend network design

## Status and ownership

Prepared design with a [locally tested implementation](../host-network/nautobot/README.md),
not deployed. The first execution scope is the separately frozen standby route;
it does not authorize the remaining network stages. The user authorized design
preparation on September 22, 2026. No host contact or live change is part of this
step. The [retained preflight](nautobot-startup-network-preflight.md) establishes
the source discrepancy and missing backend enforcement; it does not prove access
control. The existing permanent-source allowlist remains unchanged.

`homelab-network` owns this policy and host-network implementation. Proxy network
changes require coordination with `homelab-dns`, which owns those HA hosts and
Keepalived. `homelab-server-configs/Caddy` owns Caddy configuration and publication;
Nautobot owns runtime binding and startup dependencies. This document does not
activate a second Nautobot operation or authorize Caddy publication.

## Proposed source selection

Use a destination-specific, directly connected IPv6 host route on each proxy:

| Proxy | Destination | Interface | Preferred source |
| --- | --- | --- | --- |
| pihole0 | fd36:5aa8:6971:1::170/128 | eth0 | fd36:5aa8:6971:1::53 |
| pihole00 | fd36:5aa8:6971:1::170/128 | eth0 | fd36:5aa8:6971:1::54 |

Do not set a gateway for this on-link route. Do not change default routes,
address labels, RA handling, VIPs or source selection for other destinations.
IPv4 currently selects the intended .53/.54 sources and needs no proposed change.
The host route affects all unbound IPv6 clients to this one destination, including
Caddy; record that scope. An explicitly bound socket can override preferred source,
so actual Caddy connections remain an acceptance requirement.

Persist the route through each host's existing network manager, after confirming
its identity, active profile UUID and installed support for IPv6 preferred-source
routes. NetworkManager documents the `src` route attribute, but the installed
version and safe reapply behavior are not yet qualified. Do not assume the proxies
use the same manager/profile as Nautobot. If this path is unsupported, stop and
prepare a Caddy-owned, per-family transport-binding alternative; do not add the
VIP to the allowlist or change the whole network configuration as a fallback.

On each node, verify the selected source for the actual Caddy UID, both with and
without VIP ownership. Stage standby first; a controlled HA transition and the
second-node change require their own explicit scope. No connection down/up or
proxy restart is implicit in this design.

## Cluster availability during route changes

A brief interruption on the changed node is acceptable if the cluster continues
serving and the node recovers. Retain the destination-specific route approach;
there is no need to redesign Caddy source binding solely to avoid a transient
standby FAULT. Apply to one standby at a time, verify cluster DNS/HTTPS service
throughout, and prove recovered node health before acceptance or later changes.
The [retry procedure](../host-network/nautobot/RETRY_PREPARATION.md)
defines the proposed bounded recovery and rollback checks. It does not authorize
intentional failover, changes on both nodes or execution of a new bundle.

## Proposed backend enforcement

Install a component-owned `inet` nftables table named `nautobot_backend` on
j2-svpi4mf. Use a filter base chain at `prerouting` priority -110, with policy
accept. This is before conventional destination NAT (-100), but after conntrack
and its defragmentation. Matching the host destination before translation avoids
relying on an INPUT-only assumption for container port publishing. Confirm the
actual rootless Podman ingress path and hook ordering during qualification.

The rule intent, in order, is:

1. Leave loopback ingress unchanged for SSH-tunnel recovery.
2. For TCP to 10.1.2.170:8080, allow sources 10.1.0.53 and 10.1.0.54 through this
   guard, with counters; drop all other sources to that destination/port.
3. For TCP to [fd36:5aa8:6971:1::170]:8080, allow permanent ::53 and ::54 through
   this guard, with counters; drop all other sources to that destination/port.
4. Leave all other traffic unchanged for subsequent policy evaluation.

Apply on every non-loopback ingress interface, not only eth0. Do not flush the
ruleset, create a broad default-deny policy, alter NAT, or modify container-owned
tables. Do not place a blanket established/related exemption before these rules:
that could retain a previously unauthorized backend connection. Established
management/monitoring traffic is outside the destination/port match and remains
unchanged. An accept here does not override drops in other chains.

The runtime must retain its exact IPv4, permanent ULA and recovery-loopback binds;
no wildcard, global-IPv6 or extra-address listener is permitted. The guard is an
address allowlist, not cryptographic client identity or protection against a
compromised proxy/source spoofing on the trusted LAN. Database and Redis ports
remain unpublished. No global outbound filtering is introduced.

## Persistence and startup dependency

Prepare a dedicated root-owned rules artifact and idempotent loader/service under
the network owner. Load only this table atomically; validate with the installed
nft parser before mutation. Refuse an existing unowned table or changed baseline.
Do not enable a distro nftables unit whose default configuration flushes other
rules. Preserve any existing firewall service and its configuration.

The persistent guard must be loaded before application startup and verified by
rule readback, not merely by a service being active. Define the cross-system/user
systemd startup ordering for the rootless Nautobot account explicitly; a user-unit
After= reference to a system unit is insufficient. Startup must fail closed when
the expected guard is absent or differs. Administrative removal of the guard must
stop the web listener first. The final implementation must include a boot/order
qualification plan; no reboot is authorized here.

## Deployment and exact rollback requirements

Before building an authorization bundle, preserve protected copies, metadata and
hashes of each changed network profile, route state, rules artifact and service
unit; record absent files/tables explicitly. Capture unrelated rules for comparison,
not wholesale restoration. Record host identity, boot ID, manager versions, Caddy
UID, active HA owner and existing connections. Check for policy routing, earlier
DNAT, flow offload or other rules that would invalidate the proposed hook path.

Prepare separate owner-scoped operations in this order:

1. Qualify and apply permanent-source selection, standby first, with HA safeguards.
2. Install the target guard and its persistence while the application is stopped.
3. Exercise a bounded disposable listener on the intended addresses, remove it,
   and prove cleanup. Do not start the application, database or worker to test rules.
4. Pass the resulting evidence to the separate Nautobot startup operation. Confirm
   actual Caddy traffic sources when its route is later published by its owner.

Each mutation operation needs an exact hashed bundle, command, targets, numerical
timeouts and a node-local rollback guard that survives controller loss. Freeze
those after local implementation/tests; this document is not an executable bundle.

Rollback is scoped to owned objects: remove the exact added /128 route and restore
its prior profile property (or prior route) with original metadata; restore the
prior owned table atomically, or delete only that table if originally absent;
restore/remove owned service and rules files according to the captured baseline.
Never restore a full ruleset over subsequently created container rules. Detect
concurrent changes and stop for manual recovery rather than overwriting them.

If a listener has started, stop and verify it closed before removing the guard.
The timeout recovery path must follow that same order. If listener shutdown cannot
be proved, retain the restrictive guard and report manual intervention. Restore
proxy routing while the target guard remains installed. Recheck SSH, DNS/HA health,
Webmin and Munin after recovery. Exact rollback commands and console fallback are
mandatory bundle inputs, not deferred until failure.

## Acceptance matrix

Use new TCP connections, explicit address families and bounded timeouts. Capture
source/destination metadata and guard counter deltas, not application credentials.
A refusal from a closed listener is not a deny result. Prove listener health from
an allowed source before and after each negative test.

| Check | Required evidence |
| --- | --- |
| Each proxy, IPv4 and ULA | Successful controlled response; expected permanent source |
| Both HA ownership states | Same permanent source from each proxy; existing HA/DNS health |
| Munin master 10.1.3.83, both families | No response/connection; matching guard drop delta; fresh selected ULA |
| Local recovery | 127.0.0.1:8080 works through approved SSH recovery path |
| Administration | New and retained SSH connections; Webmin reachable from approved LAN |
| Monitoring | Successful Munin TCP4949 polling from 10.1.3.83 |
| Other traffic | DNS, RA/ND, outbound connectivity and unrelated rules unchanged |
| Persistence | Reload idempotence and verified ordering; separately authorized boot validation |
| Cleanup/recovery | Disposable listener absent; rollback restores only owned state |

Raw packet details, addresses and captures remain private. No external IPv6 test
host is available: retain that limitation. Same-subnet denial tests do not establish
an end-to-end Internet denial result. A temporary test client bound to a permanent
address does not prove unbound Caddy source selection; keep these results separate.

## Next implementation boundary

Implement and locally test the narrow route and nftables paths, startup guard
contract, counter-based acceptance collector and rollback behavior. First close
the retained-evidence gaps about proxy manager/version and target ingress/persistence;
collect only missing facts under a bounded read-only scope if needed. Cover wrong
host/profile, conflicting route/table, partial apply, controller loss, rollback
failure, idempotence and preservation of unrelated policy. Then freeze the first
owner-scoped operation for live authorization. The first route bundle has its own operation procedure and hash; subsequent scopes
remain inactive. See the implementation for current validation and boundaries.

## Technical references

- [NetworkManager route attributes](https://networkmanager.dev/docs/api/latest/nm-settings-nmcli.html):
  preferred-source route configuration; installed compatibility remains to be checked.
- [nftables chain hooks and priorities](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains):
  pre-NAT ordering and the distinction between accept and final drop verdicts.
