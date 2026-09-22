# Backend guard installation operation

## Scope

One target: `ama@10.1.2.170`, identity j2-svpi4mf, Nautobot UID999.
Kind `guard_install` installs the fixed TCP8080 source policy, seven artifacts,
root persistence unit and user-manager ordering. It preserves the accepted proxy
routes. No application/container/test-listener startup, HA transition, package
change, reboot or Caddy publication is included. Exact-bundle execution approval
is required. The recorded preflight is a baseline, not current authorization.

## Retry baseline

The failed predecessor stopped before production installation. Its protected
staging is archived under its original bundle hash; the active staging path was
verified absent. The corrected command helper uses `/` as its working directory
so rootless checks do not inherit an inaccessible administrator home. The retry
retains all first-install absence checks and refuses any new residue.
See [staging reconciliation](guard-staging-reconciliation.json). The predecessor
bundle remains unchanged and must not be rerun.

## Execution

Run the frozen launcher with `--bundle ABSOLUTE_BUNDLE_DIRECTORY` and
`--approved-sha256 EXACT_APPROVED_HASH`. It verifies the manifest and all file
hashes, copies the inputs into a protected `/tmp/nautobot-route-execution-*`
directory, verifies again and invokes `ansible/guard.yaml` for the one target.
It uses strict SSH host keys and noninteractive sudo. The evidence directory name
is shared with the existing route runner; this operation does not apply routes.

Before host staging, controller probes require SSH, TCP22/10000 in both families
and a successful IPv4 Munin `fetch load` from `pi@10.1.3.83`. Webmin certificate
trust and Munin IPv6 ACL repair are separate follow-ups. Neither is silently
marked fixed or added to this deployment.

The node refuses unexpected identity, owned files/units/state, unrelated firewall
rules, application activity, a listener or rootless container residue. It checks
the rules with the installed nft parser before production changes. Preparation
captures boot and unrelated-rule identity. Staged root-owned evidence is retained
if a pre-mutation check fails; do not rerun over that evidence.

The controller bounds Ansible to 240 seconds. Before production files/rules are
installed, a node-local 300-second rollback timer is armed and verified active.
Each node helper command is bounded to 20 seconds; management probes run in
parallel with 5-second connection/15-second SSH bounds. Independent readback is
bounded to 30 seconds. Controller loss leaves the watchdog armed. A timeout is
not acceptance and does not authorize a retry.

## Acceptance

Require exact installed file hashes/modes, semantically identical effective table,
unchanged boot/unrelated rules, no TCP8080 listener or running application, active
and enabled guard service, both Requires/After dependencies on user@999, and
successful read-only verification as Nautobot via its narrow sudo permission.
Do not restart the existing user manager. Verify controller management and Munin
checks before acceptance. The locked node state is marked accepted before the
watchdog is disarmed; an expired accepted watchdog is a no-op.

The controller independently requests node `report`, which repeats installed
checks and requires an inactive timer, then repeats health checks. A failed
Ansible result or failed final readback never becomes controller acceptance from
an accepted label alone. Retain all discrepancies for investigation.

This accepts installation only. It does not prove packet allow/deny behavior,
Caddy traffic, application operation or reboot persistence. The local namespace
packet test covers nft semantics only. The next packet stage needs its own
listener, counter-delta, dual-stack client and cleanup approval.

## Recovery

On install failure Ansible invokes the staged rollback helper. On controller
loss the independent timer invokes the same helper. Recovery and acceptance share
an exclusive lock. Recovery refuses drifted files, changed boot or unrelated
policy, and any TCP8080 listener. It removes only the owned table and seven files,
disables/stops the owned unit, reloads systemd, verifies absence and stopped
application state, records `rolled_back`, then stops the timer. Empty owned
directories and protected tools/evidence remain intentionally.

Failure records `manual_intervention` with bounded diagnostics; restrictive rules
remain when safe removal cannot be established. No full-ruleset restoration,
proxy change or reboot is permitted. Use previously confirmed console/physical
recovery if SSH fails. Do not retry or discard evidence automatically.

For an explicitly reviewed recovery, the node command is:

```text
cd / && sudo -n /usr/bin/python3 -I /var/lib/nautobot-backend-install/rollback_install.py
```

It is a no-op after acceptance. Later rollback of an accepted deployment requires
a separate operation that first proves no listener and preserves the accepted
archive; do not edit the state to bypass that boundary.

## Publication and evidence

Keep raw target logs in private evidence; publish only sanitized decisions and
hashes. Preserve the exact consumed bundle and result in an annotated published
tag before cleaning the stream. The freezer's local nft parser runs only in a
new user/network namespace; it must not be run against a homelab network namespace.
