# Backend network operation procedure

## Historical first execution scope: standby route

Target pi@10.1.0.54, actual hostname j1-svpihole00, NetworkManager 1.42.4,
active eth0 profile 3078e1cc-2e08-3745-b5e4-a60426628c39. Expected source is
fd36:5aa8:6971:1::54 for destination fd36:5aa8:6971:1::170/128.
Only this destination-specific preferred-source route is added. No VIP, gateway,
DNS record, Caddy configuration, application listener or target firewall changes.
The standby's current default source is already ::54; the persistent host route
makes that choice independent of future VIP ownership. The HA transition needed
to prove that latter condition remains separately scoped.

The approved execution command will have this form, using the frozen runner:

```bash
python3 /tmp/FROZEN-BUNDLE/scripts/run_bundle.py \
  --bundle /tmp/FROZEN-BUNDLE --approved-sha256 APPROVED_SHA256
```

The runner verifies every hashed input, copies the exact bundle into a protected
local workspace, verifies it again and calls Ansible for only the standby. It uses
strict SSH host keys and no password/secret material from the bundle. The playbook
stages reusable helpers/policy, arms a node-local 300-second rollback timer, then
runs the narrow transaction. The controller wait is bounded at 600 seconds; every
node command is bounded at 25 seconds. Controller loss does not cancel the timer. This transient timer does not survive
a node reboot: an unexpected boot change blocks acceptance and requires the
retained profile recovery procedure; reboot is outside this operation.

The transaction checks host, active profile, manager version, permanent source,
absence of a destination route and absence of either HA VIP. It preserves the
original profile bytes and metadata privately before writing. Reapply must leave
addresses unchanged and select ::54. Acceptance requires fresh controller SSH
reachability, healthy Caddy/Keepalived/Pi-hole/Unbound, direct DNS answers over both
permanent families, and a final route lookup for Caddy's actual UID. The node state
is marked accepted under the same lock as expiry recovery before its timer is
stopped. The controller reads back a sanitized state summary independently.

These checks accept only the standby route. They do not accept the primary route,
backend firewall, Caddy-to-Nautobot traffic, VIP failover, reboot persistence or
Nautobot runtime. Those stages require their own frozen operations.

## Retry availability boundary

The user accepts a brief standby interruption while the cluster continues serving
and the node recovers. The [retry contract](RETRY_PREPARATION.md#selected-retry-approach)
keeps the existing route implementation: proposed 60-second node recovery,
60-second stable validation, cluster probes every five seconds and the existing
300-second rollback watchdog. A transient FAULT alone is not an abort condition;
failed cluster service, persistent node failure or incorrect route state is.
The contract is implemented and locally tested; execution needs a new approved
`standby_route_retry` bundle. It also authorizes read-only controller probes to
the primary and both cluster VIP families during the standby-only mutation.
The first-install command above must not be reused against retained failure state.

## Recovery

Before profile mutation, failure leaves only inert helper/policy and protected
operation files. After mutation, the playbook rescue and independent expiry timer
both invoke the same locked rollback path. It restores exact profile bytes and
metadata, reloads that one keyfile and reapplies eth0, then verifies the prior
route property and removal of the owned /128 route. It never cycles the link,
restores all routes, or alters HA ownership. Profile or route drift causes explicit
manual intervention instead of overwriting another change.

For a separately authorized rollback after acceptance, the exact node command is:

```bash
sudo /usr/bin/python3 -I /usr/local/lib/nautobot-network/proxy_route.py \
  rollback pihole00 3078e1cc-2e08-3745-b5e4-a60426628c39
```

Protected state at `/var/lib/nautobot-proxy-route/state.json` includes the original
profile and must not be published. Reusable helper/policy files remain installed;
they are inert unless invoked. Preserve terminal evidence before clearing state.
If SSH is unavailable, wait for the timer and retry the permanent address; if
recovery remains unavailable, use console/physical recovery with the saved profile. Confirm that recovery
access for this standby is available when scheduling execution. Do not restore another host's backup or trigger an unreviewed HA switch.

## Later guard stage

`ansible/guard.yaml` installs only the owned table/service/verifier and the
user@999 startup-order drop-in, with an independent 300-second recovery timer.
It requires an absent-file baseline and no 8080 listener. Its protected installation
manifest hashes each production artifact. Drift or a listener prevents unsafe
removal. Recovery retains evidence and empty owned directories, never flushes
unrelated tables. The root verifier checks actual rule semantics before every web
start; unit activity alone cannot satisfy that check.

The guard installation does not perform packet acceptance or start an application.
Before startup, a separate bounded listener operation must exercise both proxy
sources, nonproxy denial/counter correlation, loopback recovery and unchanged
management/monitoring. Actual Caddy sources, both HA states and boot persistence
remain their respective owner gates. Keep the primary route and guard operations
inactive until the standby result is reviewed and archived.

## Current retry execution scope

Freeze with `scripts/freeze.py DESTINATION standby_route_retry`, then execute only
that frozen runner with its exact approved SHA-256. The runner performs read-only
SSH health collection on pi@10.1.0.53 and pi@10.1.0.54 plus IPv4/IPv6 DNS and HTTPS
probes from the controller. Strict host keys, passwordless scoped sudo for the
read-only Python collector and normal HTTPS certificate trust must already work;
failed baseline checks stop before node staging.

Only pi@10.1.0.54 is mutated: preserve predecessor artifacts in the protected
archive, replace verified route helpers/policy, arm the distinct 300-second retry
watchdog, add the single preferred-source route and reapply eth0. No primary
mutation, deliberate VIP transfer, dispatcher change, firewall installation or
application startup is included. Standby console/physical recovery was confirmed
by the user for this operation; retain that availability during execution.

The existing helper owns exact profile rollback. The newly installed helper stays
available for recovery; archived prior helpers and raw state are retained rather
than automatically restored over new evidence. On failure after state archival
but before route mutation, leave that inert residue and stop for review. No route
rollback is necessary if the new transaction never wrote a profile. On unreachable
SSH or controller loss, allow the node timer to finish, then inspect its journal
and state; an inactive timer alone is not proof of recovery.

Controller evidence contains timestamped health history, failure status, Ansible
output and a sanitized node report. Raw profile backups stay root-private on the
node. Success accepts this standby route only. Primary source selection, target
guard deployment and application startup remain separate operations.
