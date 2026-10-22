# IP address inventory

[hosts.yaml](hosts.yaml) owns the explicit host allocations listed here. It is
an initial scoped inventory, not an assertion that unlisted addresses are free.
Host membership belongs to server inventory; authoritative records belong to
`homelab-dns`. Allocation does not authorize assignment or DNS deployment.

The operator selected static host IPv4 `10.1.3.83/22` and static ULA
`fd36:5aa8:6971:1::83/64` for `svmf`. The intended names are `svmf.local.theama.co` and
`munin.local.theama.co`; IPv6 publication was accepted October 21, 2026. Reverse DNS uses canonical
`svmf.local.theama.co`. Preserve the verified IPv4 DHCP reservation while changing
the host to static addressing; a reservation alone is not host-static setup.
The previous generated ULA is historical observed state, not the new allocation.

The approved readiness capture confirmed runtime gateway `10.1.0.1` and both
DNS VIPs. The operator selected an explicit static ULA alongside RA-provided
global IPv6 and default routes. `gateway: null` now deliberately means no pinned
IPv6 gateway; `gateway_source: router_advertisement` defines routing. Both DNS
VIPs and the search domain are explicit, with automatic DNS disabled. The
[settings candidate](../Ubiquiti/munin-master-profile/static-settings.json) is the
reviewed value source. The October 21 operation committed static IPv4 and the
fixed ULA with independent dual-stack SSH/HTTPS acceptance, retained RA routing
and persisted profile checks. Physical reboot/renewal persistence remains
unobserved. See the [accepted network review](../Ubiquiti/svmf-static-network-review.md#current-checkpoint--october-21-2026).
The exact backup and consumed operation state remain retained. Munin/svmf IPv6
DNS publication passed October 21 at 10:12:30 CDT; monitoring/client refresh
acceptance remains separate and pending.
