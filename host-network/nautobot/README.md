# Nautobot backend network candidate

Reusable network implementation; both recorded proxy preferred-source routes are accepted.
The [guard installation](guard-retry-result.json) is also accepted, with its archive tag published and verified. [Live packet qualification preparation](PACKET_QUALIFICATION_PREPARATION.md)
defines the next bounded listener stage. Application startup and packet execution remain
separate stages requiring their own approved execution bundles.
The [network design](../../Ubiquiti/nautobot-backend-network-design.md) owns scope.
Clients continue using the HA VIP; outbound backend connections select each proxy's permanent address. The primary operation used a temporary HA handoff and restored
the original VIP ownership.

## Current accepted scope

The [primary result](primary-result.json) records successful handoff, route
convergence and failback. Independent readbacks passed; both 60-second stability
windows passed. Brief transition probe failures remain explicit in the result.
Primary terminal Git archival is published and verified; do not rerun its consumed bundle.
Next is the [backend firewall preparation](BACKEND_GUARD_PREPARATION.md):
the completed read-only preflight and implemented installation path are recorded
there. See [guard installation](BACKEND_GUARD_OPERATION.md) for execution bounds.

The [standby retry result](retry-result.json) accepts the permanent-source route
on pihole00 only. Route convergence completed in about six seconds; sampled
cluster health passed and the node remained BACKUP. The short node-local IPv6
health failure recovered without a recorded FAULT transition. The dispatcher
warning remains. Do not rerun the consumed retry bundle. The published terminal commit/tag is recorded in [history](HISTORY.md). [Primary preparation](PRIMARY_PREPARATION.md) and the [primary operation](PRIMARY_OPERATION.md) preserve the executed scope.

## Implemented paths

- Fixed policy compiler: unchanged permanent-source allowlist and TCP8080 scope.
- NetworkManager route helper: wrong-host/profile/route/address/HA checks, saved
  prior route property, bounded reapply, source readback and scoped route removal.
  A node-local five-minute systemd timer survives loss of the controller. Acceptance
  marks state under the same lock before disarming the timer; expired accepted
  operations do not remove their route. The first playbook targets standby only.
- nftables guard: atomic first install, installed-table semantic verification,
  idempotent no-op, drift refusal, and removal refusal while 8080 is listening.
  Counter values and handles are excluded from comparison; verdict/order are not.
- Persistence unit and user@999 system-manager ordering; web ExecStartPre invokes
  the fixed read-only root verifier through a narrowly scoped sudoers command.
  This closes the cross-system/user ordering gap without granting general nft access.
- First-install file rollback helper refuses changed artifacts, keeps a guard if a
  listener remains, and removes only owned files/rules. It preserves evidence.
- Offline bundle freezer and unit/isolated real-kernel packet tests.

## Historical retry preparation after executed failure

The first route bundle was consumed and rolled back. Follow-up found an eight-second
Keepalived FAULT interval caused by failed IPv6 Caddy health checks. The user accepts brief node interruption with cluster service continuity and
node recovery. Keep the existing route approach; new deployment bundles remain
available through the separately approved retry path with recovery checks and
protected residue reconciliation.
See [diagnosis and retry preparation](RETRY_PREPARATION.md). The source helper now
retains command-specific diagnostics and bounded settlement evidence; that does not
establish live retry acceptance.

## Historical first-operation activation boundaries

The consumed first scope was **standby route only**, through `run_bundle.py` and
an exact frozen `standby_route` bundle. It targets pi@10.1.0.54 and its observed
NetworkManager profile, requires the actual standby role, and does not move VIPs.
It verifies permanent source selection, direct DNS in both families, service state
and controller SSH reachability before disarming the five-minute rollback timer.
A separate node report is required before the controller reports success.
See [the operation procedure](OPERATIONS.md) for the exact scope and rollback.

The route helper preserves exact profile bytes, owner/mode/times and the prior
route property in protected node-local evidence. Concurrent changes block an
unsafe overwrite. An interrupted profile write is reconciled only if unrelated
profile fields and the remaining route property match the saved state. Recovery
uses the existing manager's load/reapply path, never connection down/up.

Read-only follow-up confirmed proxy NetworkManager 1.42.4, Nautobot 1.52.1, and
Nautobot UID 999. Proxy logical names differ from hostnames (`j1-svpihole0`,
`j1-svpihole00`). The standby's installed offline nmcli parser accepted the exact
IPv6 `src` route. Its GENERAL.FILENAME field is unsupported; profile discovery
therefore matches a unique persistent keyfile by UUID. This performs no live
profile write. Runtime reapply and controlled HA transitions are now qualified by the route results; reboot persistence remains untested.

The guard playbook now includes independent timed recovery, first-install absence
checks, exact artifact hashes and a no-listener acceptance gate. It installs the
root system-unit ordering and sudo verifier but does not start Nautobot. Its
artifacts are included for review in the first bundle, **not authorized by the
route launcher**. Target parser readback, live packet acceptance and later boot/HA
qualification remain separate. The full firewall ruleset is never flushed.
Root-owned recovery evidence/tools and empty owned directories remain after rollback
for diagnosis; changed production files and the owned table return to their saved
absent state. First-install guards refuse existing files or operation evidence.

A `review_only` bundle is not executable. A `standby_route_retry` bundle enables only
the fixed retry route runner; the consumed first-install kind is refused. Neither permits running the guard playbook directly,
listener tests, primary-node mutation, reboot, failover or application startup.
Existing Nautobot operation state remains clean.

## Local validation

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s host-network/nautobot/tests -p 'test_*.py'
unshare --user --map-root-user --net \
  python3 host-network/nautobot/tests/packet_namespace.py
python3 host-network/nautobot/scripts/freeze.py /tmp/NEW-REVIEW-BUNDLE
```

The namespace test requires local user/network namespaces and root-mapped
capabilities; run outside the filesystem sandbox. It refuses the initial network
namespace, does not contact any homelab host, and tears down its child namespace.
It tests real nft parsing, allowed permanent sources, denied nonproxy/VIP sources,
unchanged management/monitoring ports and scoped rule-removal recovery. These are
local kernel results, not live Caddy/HA/Podman or reboot acceptance.

[NetworkManager 1.42.4 route reference](https://networkmanager.dev/docs/api/1.42.4/nm-settings-nmcli.html)
provides the version-specific route syntax.
