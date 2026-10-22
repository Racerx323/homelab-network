# NTP IPv6 egress permit candidate

Status: v2 policy and TCP acceptance completed; both permits remain enabled.
V1 held before mutation. This document does not authorize another live operation.
The NTP plan and operations remain owned by `homelab-ntp`; this repository owns
the firewall transaction and address-management decision. Follow
[UNIFI_ACCESS](../UNIFI_ACCESS.md) for credentials and verified local-controller
access. The operator selected automated API execution and confirmed full
read/write capability for `AUDIT_LOCAL`; the credential name is not its role.

## Separate Munin master reservation inspection

The standalone `inspect-munin-source.py` prepares a read-only review for the
existing Munin master's DHCP reservation. It is independent of the IPv6 permit
transaction below and does not reuse its write-capable execution client.
The operator chose to preserve current networking and verify the reservation
and stable ULA policy. Alert ownership belongs to the native master; the Munin
repository owns contact/metric configuration.

Seal offline with `seal --directory NEW_PRIVATE_DIRECTORY`. After separate
approval of the archive SHA-256, `execute --directory DIRECTORY --sha256 HASH`
allows only the fixed integration-client GET and a legacy reservation-collection
GET, after DNS/TLS precheck. The legacy endpoint is unqualified with the current
credential; unsupported responses remain gaps. No login/write fallback exists.
Only the matching MAC's reservation fields are retained; no other client data,
credential, raw controller response or network change is persisted. See the
generated review for exact endpoints, bounds, expiry and single-use behavior.
The master-local effective IPv6 policy check is a separately approved NTP stage;
neither snapshot alone proves renewal/reboot persistence.

The approved reservation inspection completed October 20, 2026. Controller
DNS/TLS, the fixed integration-client identity and the legacy reservation GET
passed. Exactly one matching record enabled the existing IPv4 reservation and
matched the master's observed source address. No network change occurred.
The separate master-local check supports stable ULA generation under upstream
defaults; saved-profile/installed-default and renewal/reboot evidence remains
open in the NTP readiness checklist. Both executed stages are consumed.

The later corrected saved-profile inspection found the active keyfile in `/run`.
The [network-owned persistence proposal](../munin-master-profile/README.md) saves
the same UUID/settings without reactivation. It requires separate mutation
approval and has not executed; the IPv4 reservation remains unchanged.

## Host identity instead of a global-address list

Use one explicitly observed Ethernet MAC as the source of two IPv6-only policies:
UDP 123 and TCP 4460 from the host's Default LAN source zone to External. The
accepted node evidence supplies the MAC; fresh evidence must reproduce it and
show all public upstream routes using `eth0` before mutation. Do not assume the
management ULA is the public egress address or copy a leased global `/128` into
a permanent list. Destination addresses remain unrestricted within External,
matching the existing IPv4 permits' destination scope; only these two protocol/
port combinations and this source MAC are added.

The proposed source match does not contain the ISP prefix or host global address,
so no scheduled address-list updater or write credential on the NTP host is
needed. Keep ordinary RA/SLAAC and existing IPv4/ULA configuration. A replacement
NIC, changed/randomized MAC, different interface or routed downstream placement
requires a new identity check and reviewed policy update. MAC matching is a
network source selector, not cryptographic host authentication. Actual IPv6
forwarding behavior must pass the post-change probes; prefix rollover is not
tested by this operation. Do not fall back to a whole-LAN permit or an IID/IP
filter if the MAC match fails.

The operator considered UniFi's `IPV6_IID` source selector and explicitly chose
MAC matching with no host address change. Retained evidence does not establish
a prefix-independent IID; adopting that selector would need a separate review
of host address-generation settings and any fixed-IID configuration.

Ubiquiti documents source-MAC and IP-version filters in
[Zone-Based Firewalls](https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi).
The API contract is the operator-supplied
[Network v10.6.106 documentation](https://developer.ui.com/network/v10.6.106/gettingstarted)
and its [OpenAPI schema](https://developer.ui.com/network/v10.6.106/openapi.json).
The schema defines `MAC_ADDRESS` with
`macAddressFilter.macAddresses`, and `PUT` for zone-pair policy ordering.
The captured controller reports Network 11.0.83; stop on unsupported schema or
method. Do not switch to a legacy/cloud API or retry a write with another method.

## Prepare

`prepare.py` reads the accepted, closed NTS transport inspection and the original
recovered cutover evidence. It binds controller policies, zone ordering, referenced
lists, host identity, current execution inputs and the public API schema hash.
It prepares fresh `before`, `after` and conditional `recovery` diagnostic bundles
using the checked-in NTP inspection tool. Each bundle has a unique operation ID,
protected root-owned target staging, one controller capture, one node capture,
matching dual-endpoint readback and diagnostic closure. Prior bundles are never
modified. The resulting private review and parent archive require separate
execution approval for both controller and NTP host.

Invoke preparation with explicit accepted-evidence, NTP-repository, original
cutover-source, original-cutover SHA-256, operation ID, downloaded OpenAPI and
new private output paths. `prepare.py --help` lists these local arguments.
No controller, Doppler or target access occurs during preparation. Never commit
the private archive, receipts, MAC/address evidence or controller snapshot.

## Apply and accept

The approved parent `run.py --mode apply` checks its archive and bound execution
inputs, registers once under an exclusive local lock, then:

1. Runs fresh before-diagnostics and verifies identity, routes, accepted readbacks
   and closure. Requires the controller baseline to remain unchanged.
2. Verifies controller DNS/TLS before loading the credential in memory. Preserves
   the pre-change snapshot privately. Requires a matching controller version,
   network/zone identity, all existing policies, both orderings and referenced lists.
3. Creates exactly two uniquely named policies disabled. Verifies the returned
   policy content and preserves original policy order. Records each write intent
   durably before submitting it; never retries a submitted create.
4. Inserts the two policies immediately before the existing Default LAN NTP
   reject, without changing any existing rule or its relative order. Enables only
   the two verified candidates. Existing established/related return policy stays
   in place; no generated return policy is requested.
5. Runs after-diagnostics. Requires all 12 TCP 4460 connections to the three
   configured upstreams, both families and root/NTP account contexts, to succeed.
   Requires another exact policy/order readback before accepting the permits.

API snapshots are not atomic. Coordinate an exclusive operator change window;
every detected unrelated change holds the transaction. The mutation client is
bounded to 240 API requests, 64 MiB total, 2 MiB per response, 10-second socket
timeouts and a 600-second API deadline per attempt. Each child retains its own
reviewed collection bounds. The two-hour start reserve precedes child expiry.

This accepts policy scope and TCP connectivity only. UDP 123 policy is checked,
but UDP exchange and TLS/NTS authentication remain explicit final-cutover gates.
Account probes do not reproduce the service sandbox. NTPsec/GPSD remain stopped;
no clock, receiver or host networking changes occur. No reboot or broad port
opening is included.

## Recovery and interrupted work

On failure after a possible mutation, the runner attempts recovery: list exact
operation-owned additions, verify their full match/action, disable them, delete
them, then verify original policy contents and order. It discovers a created
object even if its POST reply was lost. An unknown/broadened object or unrelated
policy drift stops recovery instead of overwriting another administrator's work.
It then runs the single recovery diagnostic and retains its observations; IPv6
refusal after removing these permits is not itself a failed recovery.

There is no independent gateway recovery timer. Workstation/controller loss may
leave these narrowly scoped permits installed until connectivity returns. The
approved `--mode recover` continuation may run once after interrupted/held apply;
it does not repeat a POST. Recovery verifies policy restoration even if a child
capture cannot finish. An interrupted or held diagnostic must use its own approved
numbered readback/cleanup continuation, never another start. Preserve all intents,
reports and logs; cleanup means diagnostic closure, not deletion of evidence.

## Offline verification

The October 13 v1 preflight captured a change to the existing IPv6 DNS allow
rule: its source now uses MAC addresses instead of the previously referenced
IPv6 address list. That list was no longer referenced by the collected policies;
its deletion was not established. Exact-baseline comparison correctly stopped
before the mutation client authenticated or submitted any firewall write.
The before-diagnostic was accepted and closed; all IPv4 TCP probes succeeded
and all IPv6 probes remained refused. No recovery was needed. V2 binds this
fresh evidence and preserves the observed DNS rule. The executed v1 archive,
registration and evidence remain intact and must not be replayed.

The separately approved v2 execution created and enabled both scoped permits.
All six IPv6 TCP probes changed from refusal to success; all six IPv4 probes
remained successful. Fresh checks covered all three upstreams under root and the
NTP account. Both before/after diagnostics had matching dual-endpoint readbacks
and completed cleanup. Existing policies, the operator's DNS rule, referenced
lists and relative order were preserved. No recovery was needed or exercised.
Private `apply/accepted.json` and `outcome.json` beside the v2 review retain
acceptance and evidence bindings. Do not replay this accepted transaction.

Next prepare the corrected NTP service-cutover review. UDP exchange, authenticated
NTS, service sandbox, clock discipline and client/mDNS acceptance remain pending.
No host addressing or clock-service activation occurred in this firewall stage.

Run `python3 -m unittest discover -s Ubiquiti/ntp-ipv6/tests -v` from the network
repository with `PYTHONDONTWRITEBYTECODE=1`. Tests exercise exact match/ports,
ordering, partial writes, lost responses, restoration, drift rejection, private
file handling and TLS-before-credential behavior. The NTP repository retains its
diagnostic transport/staging tests. V2 accepted policy writes and bounded TCP
behavior; deletion recovery and prefix rollover were not exercised live.

## Static master address-conflict inspection

`inspect-munin-source.py seal --mode conflicts --directory OUTPUT` prepares a
separate GET-only review of configured clients, active clients and network
prefixes for the desired svmf IPv4/ULA. It also rechecks master identity and the
existing reservation. The five fixed requests retain canonical TLS/DNS and
in-memory Doppler credential handling. Only matching-address owner classes,
coverage counts and typed relevant prefixes are exported; raw controller data,
unrelated clients and secrets are discarded. Unsupported endpoints/schema fail
without automatic alternatives.

This is controller evidence, not proof that the address is unused. Incomplete
IPv6 registry fields and offline/static devices remain visibility gaps. No
probe, DHCP/profile/firewall/DNS change, checkpoint or service action is included.
The conflict review and host-local recovery review need separate exact bundle
approvals before contact. The later mutation still requires qualified recovery,
complete settings, observed source selection and successful DAD.

The approved conflict inspection completed without mutation. It confirmed the
master reservation and no conflict in selected address fields across 61 configured
and 43 active clients. The selected IPv6 fields and relevant prefix fields were
not exposed. This is limited query/projection coverage, not proof of unused ULA
or missing IPv6 configuration. Preserve future authorized DAD and guarded recovery;
retain the exact consumed archive and do not replay the stage.
