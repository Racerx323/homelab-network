# Nautobot startup network preflight — September 22, 2026

Read-only collection completed. Application-network readiness remains blocked.
No firewall rules, routes, services, proxy settings or VIP ownership changed.
No application listener was started and no permit/deny packet test was attempted.

## Observed paths and sources

| Source | IPv4 source toward Nautobot | ULA source toward Nautobot | Path |
| --- | --- | --- | --- |
| pihole0 | 10.1.0.53 | fd36:5aa8:6971:1::56 | eth0, directly connected |
| pihole00 | 10.1.0.54 | fd36:5aa8:6971:1::54 | eth0, directly connected |
| Munin non-proxy vantage | 10.1.3.83 | Current on-link ULA; recheck before testing | eth0, directly connected |

Proxy route lookups were repeated for the actual Caddy service UIDs. Both Caddy
services are active. Read-only localhost admin-API configuration inspection found
two active reverse-proxy handlers on each host, neither with transport.local_address.
Only those source-binding fields were retained; full active configurations were
not stored. This is kernel source-selection/configuration evidence, not a capture
of a future Caddy-to-Nautobot connection. No Nautobot route has been published.

The primary owns the floating ::56 address as well as permanent ::53. Its current
IPv6 source selection differs from the approved permanent-address allowlist.
Do not silently add the VIP to that allowlist. Resolve deterministic source behavior
through the network/Caddy owners and validate it with both HA ownership states in
a separately reviewed operation. Permanent ::53/::54 are configured on the nodes.

## Enforcement

On Nautobot, nft list ruleset, default IPv4/IPv6 iptables-save and both legacy
iptables-save commands returned success with empty rules. nftables.service is
inactive/disabled; ufw/firewalld units are absent. eth0 ingress tc filters are
empty. No TCP 8080 listener exists. SSH, Webmin and Munin listeners remain present.
The backend allowlist is not enforced by the inspected target firewall paths.
A future connection refusal while no listener exists would not prove a deny rule.

Gateway inspection used root SSH with strict host-key verification and the existing
Doppler homelab-dev/prd_unifi SSH_PASSWORD reference; the value was not retained.
Installed iptables/ip6tables and ipsets were read successfully, without truncation.
Gateway nft is unavailable (127), so no nft result is treated as an empty ruleset.
The gateway br0 has 10.1.0.1/22 and fd36:5aa8:6971:1::1/64. Endpoints' route
lookups show direct LAN paths without a gateway next hop. Therefore the gateway's
routed FORWARD policy cannot be used as proof of the backend allowlist on these
paths. Switch ACL/offload policy was not inspected; no claim about its absence is
made. Enforcement covering same-subnet delivery is still required.

The deployed UBIOS_LAN_LAN_USER chains retain broad terminal ACCEPT rules.
UBIOS_WAN_LAN_USER retains RELATED/ESTABLISHED acceptance, INVALID drop and final
DROP in both families. These are rule observations, not fresh external tests.
They do not establish the required source-specific TCP 8080 policy.

## Selected non-proxy vantage and limits

Use the existing Munin master, pi@10.1.3.83, as the proposed internal negative-test
vantage. Read-only SSH and both direct routes succeeded. Re-read its selected ULA
at test time; its observed address is not an approved proxy and must not be added
to the allowlist. This does not change Munin TCP 4949 access or management policy.
No external IPv6-capable vantage is available from the earlier user confirmation;
external denial remains untested. Actual allowed/denied TCP tests await reviewed
policy and a controlled listener, with rule/counter correlation and route controls.

## Collection qualifications

Initial proxy SSH as ama was rejected; the owner-documented pi account succeeded.
Both attempts are retained. The unprivileged PATH lookup for iptables version
commands failed, while privileged rule collection succeeded; this is not a claim
that those tools are absent. Legacy save commands were unavailable on proxies,
but both succeeded with empty output on the Nautobot target. No package installed.

Private raw evidence, per-command statuses and hashes are in
/home/aaron/code/.local-evidence/nautobot-startup-network-preflight-20260922.
The evidence includes host and gateway addresses/rules and must not be published.

## Next concrete operation

Prepare an owner-reviewed enforcement design for Nautobot TCP 8080 that covers
same-subnet IPv4/IPv6 traffic, preserves SSH/Webmin/Munin and established traffic,
and includes exact backup/rollback and delayed activation before application
startup. Resolve the primary proxy's IPv6 source discrepancy alongside that design.
Keep the permanent-source allowlist unchanged pending that review. Revalidate
addresses, backend source selection and both HA states before relying on the rule.
Live firewall/proxy changes, HA transitions and listener activation need separate
scoped authorization; this read-only preflight authorizes none of them.

Design follow-up: [backend network design](nautobot-backend-network-design.md).
It does not alter the observed preflight results or authorize live changes.
