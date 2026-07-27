# UDM-SE dual-stack ULA and Pi-hole DNS VIP configuration

## Purpose

This document records the IPv6 Unique Local Address (ULA) configuration applied
to the `Default LAN` on July 26, 2026, and the shared Pi-hole DNS VIP
advertisement completed on July 27, 2026.

The change added an ISP-independent IPv6 prefix for stable internal services
while preserving the existing ISP-delegated global IPv6 prefix and native
dual-stack Internet connectivity. UniFi DHCP and Router Advertisement now
provide only the shared Keepalived DNS VIPs to clients.

## Platform

| Component | Version |
| --- | --- |
| Gateway | Ubiquiti Networks UDM-SE |
| UniFi OS | `5.1.27` |
| UniFi Network | `10.5.67` |
| Network | `Default LAN` |
| IPv4 gateway and subnet | `10.1.0.1/22` |

## Address plan

| Purpose | Address or prefix |
| --- | --- |
| Site ULA prefix | `fd36:5aa8:6971::/48` |
| Default LAN ULA prefix | `fd36:5aa8:6971:1::/64` |
| UDM-SE Default LAN ULA | `fd36:5aa8:6971:1::1/64` |
| `pihole0` ULA | `fd36:5aa8:6971:1::53/64` |
| `pihole00` ULA | `fd36:5aa8:6971:1::54/64` |
| Keepalived IPv4 DNS VIP | `10.1.0.55/22` |
| Keepalived IPv6 DNS VIP | `fd36:5aa8:6971:1::55/128` |

The ULA prefix remains stable if the ISP changes the delegated global IPv6
prefix.

## IPv4 DHCP configuration

In UniFi Network, the `Default LAN` was edited under:

```text
Settings > Networks > Default LAN
```

The final IPv4 DHCP settings were:

| Setting | Value |
| --- | --- |
| DHCP Mode | DHCP Server |
| DHCP Range | `10.1.0.103` through `10.1.3.254` |
| DHCP Guarding | Enabled |
| Trusted DHCP Server | `10.1.0.1` |
| DHCP Server IP | `10.1.0.1` |
| Auto Default Gateway | Enabled |
| Auto DNS Server | Disabled |
| DNS Server | `10.1.0.55` |

The Pi-hole node addresses and shared IPv4 VIP are outside the DHCP pool.
Clients receive only the shared IPv4 VIP and do not receive the UDM-SE,
individual Pi-hole nodes, or public resolvers as fallback DNS servers.

## IPv6 ULA and DNS configuration

In UniFi Network, the `Default LAN` was edited under:

```text
Settings > Networks > Default LAN > IPv6
```

The final settings were:

| Setting | Value |
| --- | --- |
| Interface Type | Prefix Delegation |
| Prefix Delegation Interface | ISP |
| Prefix Delegation ID | Auto |
| Advanced | Manual |
| Additional IPs | Enabled |
| Additional IPv6 address | `fd36:5aa8:6971:1::1/64` |
| Client Address Assignment | SLAAC |
| Auto DNS Server | Disabled |
| DNS Server | `fd36:5aa8:6971:1::55` |
| Router Advertisement | Enabled |
| RA Priority | High |

The existing delegated gateway address remained:

```text
2600:1702:7370:2f4f::1/64
```

The existing link-local gateway address remained:

```text
fe80::6ad7:9aff:fe1f:73d5
```

Prefix Delegation was not replaced with a static interface configuration.
NAT66 was not enabled. The ULA was added as a secondary prefix so clients can
use ULA and global IPv6 addresses simultaneously.

Auto DNS Server was disabled only after the shared Keepalived IPv6 VIP passed
ownership, failover, failback, and DNS tests. The UDM-SE now advertises only
`fd36:5aa8:6971:1::55` as the IPv6 DNS server. It does not advertise the
UDM-SE ULA, its ISP-delegated address, either Pi-hole node address, or a public
IPv6 resolver as fallback DNS.

## Validation from pihole00

The gateway ULA was tested from `pihole00`:

```bash
ping -6 -c 3 fd36:5aa8:6971:1::1
```

Observed result:

```text
3 packets transmitted, 3 received, 0% packet loss
```

The UDM-SE appeared as a reachable IPv6 router in the neighbor table:

```bash
ip -6 neighbor show dev eth0 \
  | grep 'fd36:5aa8:6971:1::1'
```

Observed result:

```text
fd36:5aa8:6971:1::1 lladdr 68:d7:9a:1f:73:d5 router REACHABLE
```

The global addresses on `pihole00` were inspected with:

```bash
ip -6 address show dev eth0 scope global
```

The host retained its permanent ULA:

```text
fd36:5aa8:6971:1::54/64
valid_lft forever preferred_lft forever
```

The host also retained its ISP-delegated global address:

```text
2600:1702:7370:2f4f:5d5:46f0:b951:319b/64
```

SLAAC added another dynamic ULA:

```text
fd36:5aa8:6971:1:136d:8575:71e5:dd45/64
```

The additional dynamic address is expected. It confirms that the UDM-SE is
advertising the ULA prefix with SLAAC. It does not replace or interfere with
the permanent `fd36:5aa8:6971:1::54` server address.

These tests confirmed:

- the UDM-SE owns and responds on `fd36:5aa8:6971:1::1`;
- IPv6 Neighbor Discovery works on the LAN;
- the ULA prefix is advertised to SLAAC clients;
- the permanent `pihole00` ULA remains configured; and
- global IPv6 connectivity remains available.

## Keepalived DNS VIP validation

The final Keepalived cluster uses synchronized IPv4 and IPv6 VRRPv3
instances:

| Role | Host | Priority |
| --- | --- | ---: |
| Preferred primary | `j1-svpihole0` | 150 |
| Backup | `j1-svpihole00` | 100 |

The shared VIPs are:

```text
10.1.0.55/22
fd36:5aa8:6971:1::55/128
```

The following behavior was validated:

- both VIPs are normally owned by `pihole0`;
- stopping Keepalived on `pihole0` moves both VIPs to `pihole00`;
- restarting `pihole0` preserves the VIPs on `pihole00` during the configured
  10-second preemption delay;
- stopping `pihole-FTL` on `pihole0` causes the DNS health script to fail three
  times and moves the synchronized group to `pihole00`;
- three successful health checks and the preemption delay are required before
  `pihole0` reclaims both VIPs;
- IPv4 and IPv6 DNS queries succeed through the VIPs on either owner; and
- MASTER and BACKUP notifications were delivered through Apprise to Discord
  and Pushover.

Example VIP tests:

```bash
dig @10.1.0.55 example.com A +short
dig -6 @fd36:5aa8:6971:1::55 example.com AAAA +short
```

## Windows client validation

A Windows client on Default LAN used interface `10G` and received:

```text
IPv4 address: 10.1.3.141
ULA address: fd36:5aa8:6971:1:329a:fbf1:cd87:5b72
Global IPv6 address: 2600:1702:7370:2f4f:ca57:4c38:24d1:e8e1
```

The advertised DNS servers were inspected with:

```powershell
Get-DnsClientServerAddress -InterfaceAlias "10G" -AddressFamily IPv4 |
    Format-Table InterfaceAlias,ServerAddresses -AutoSize

Get-DnsClientServerAddress -InterfaceAlias "10G" -AddressFamily IPv6 |
    Format-Table InterfaceAlias,ServerAddresses -AutoSize
```

Final result:

```text
IPv4: {10.1.0.55}
IPv6: {fd36:5aa8:6971:1::55}
```

Immediately after the UniFi change, Windows retained the previous UDM-SE
IPv6 DNS address `2600:1702:7370:2f4f::1`. Restarting the adapter cleared the
stale Router Advertisement state:

```powershell
Restart-NetAdapter -Name "10G" -Confirm:$false
Start-Sleep -Seconds 10
```

Both VIPs responded with zero packet loss:

```powershell
ping.exe -n 3 10.1.0.55
ping.exe -6 -n 3 fd36:5aa8:6971:1::55
```

Direct DNS queries succeeded:

```powershell
Resolve-DnsName example.com -Type A -Server 10.1.0.55
Resolve-DnsName example.com -Type AAAA -Server fd36:5aa8:6971:1::55
```

Queries through the Windows default resolver also returned `A` and `AAAA`
answers:

```powershell
Resolve-DnsName example.com -Type A
Resolve-DnsName example.com -Type AAAA
```

These results confirm that UniFi supplies the two shared Pi-hole VIPs and that
the Windows client can reach and use both address families.

## Rollback

### DNS advertisement rollback

To stop advertising the Pi-hole VIPs without removing the ULA:

1. Open `Settings > Networks > Default LAN`.
2. Under IPv4 DHCP, remove `10.1.0.55` and enable Auto DNS Server, or enter the
   intended replacement DNS server.
3. Under IPv6, remove `fd36:5aa8:6971:1::55` and enable Auto DNS Server, or
   enter the intended replacement IPv6 DNS server.
4. Apply the change.
5. Reconnect client adapters or wait for the prior DHCP and RA information to
   expire.

### Full ULA rollback

To remove the ULA from UniFi Network:

1. Open `Settings > Networks > Default LAN > IPv6`.
2. Remove `fd36:5aa8:6971:1::55` as the custom IPv6 DNS server.
3. Enable Auto DNS Server or configure another reachable IPv6 DNS server.
4. Leave Interface Type set to Prefix Delegation.
5. Remove `fd36:5aa8:6971:1::1/64` from Additional IPs.
6. Leave SLAAC and Router Advertisement enabled.
7. Apply the change.

Do not disable Prefix Delegation or remove the ISP-provided global IPv6
configuration as part of this rollback.

After rollback, confirm that global IPv6 still works:

```bash
ping -6 -c 3 2606:4700:4700::1111
```

The permanent ULA on `pihole00` can remain configured while troubleshooting,
but it will not provide network-wide ULA communication without the UDM-SE ULA
and router advertisement.

## Final state

The UDM-SE and Pi-hole dual-stack DNS configuration is complete:

- Prefix Delegation continues providing native global IPv6.
- The stable ULA prefix is advertised through SLAAC.
- The UDM-SE provides the stable ULA gateway.
- UniFi DHCP advertises only the IPv4 DNS VIP.
- UniFi RA advertises only the IPv6 DNS VIP.
- Keepalived moves both VIPs together.
- Windows successfully uses both VIPs.

The related node configurations are recorded in:

- [pihole0 IP configuration](pihole0-ip-configuration.md)
- [pihole00 IP configuration](pihole00-ip-configuration.md)

Detailed Keepalived deployment and Windows validation runbooks are stored in
the `homelab-dns` repository:

```text
Keepalived/docs/keepalived-dual-stack-runbook.md
Keepalived/docs/windows-dual-stack-dns-validation-runbook.md
```
