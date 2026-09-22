# Backend firewall installation preparation

## Latest execution

The first guard installation stopped before production changes; see
[guard-result.json](guard-result.json). Protected node staging has now been archived by exact hash and independently
copied/verified locally; see [reconciliation](guard-staging-reconciliation.json).
The active staging path is absent and the local working-directory correction is
tested. A retry requires a new exact-bundle authorization. Do not rerun the consumed
bundle or interpret the earlier absent-directory preflight as current.

## Scope and gate

Both proxy preferred-source routes are accepted. This is the next, separate
network-owner operation on `ama@j2-svpi4mf.local.theama.co` (10.1.2.170).
The separately authorized read-only preflight is complete; see
[its review](BACKEND_GUARD_PREFLIGHT.md). Execution remains unauthorized. The guard installation path is implemented; the frozen bundle is governed by
[the operation procedure](BACKEND_GUARD_OPERATION.md).

Install only the component-owned `inet nautobot_backend` table, seven fixed
artifacts, persistence service and UID999 user-manager dependency defined in
`ansible/guard.yaml` and `scripts/rollback_install.py`. Leave application services
stopped and TCP8080 closed. Preserve administration, Webmin, Munin and unrelated
rules. Do not change either proxy, DNS, Caddy configuration, packages or HA roles.
The owning [network design](../../Ubiquiti/nautobot-backend-network-design.md)
remains the policy authority.

## Completed bounded read-only preflight

Collect on the target, with protected output and separate exit status:

- Hostname, boot ID, permanent addresses, UID999 identity and recovery access.
- Installed nft/systemd/Podman versions, current firewall service state and
  effective IPv4/IPv6 rules, hook priorities, DNAT, flow offload and policy routing.
- Listener inventory and Nautobot user-unit/container state: no TCP8080 listener
  and application services stopped. Do not start a container or run SMART queries.
- Absence or exact metadata of the seven owned paths in `rollback_install.ALLOWED`,
  the owned table, `/var/lib/nautobot-backend-install`, rollback unit/timer and
  any existing user@999 drop-ins. Existing or ambiguous state stops first install.
- Current SSH/Webmin reachability; Munin polling from `pi@10.1.3.83`, including
  its selected IPv6 source for the later packet stage. Record unavailable evidence.

Scoped host-contact authorization was supplied for the target and Munin master;
this does not extend to deployment. Retain existing accepted proxy-route evidence; do not reapply routes.
Raw rules and addresses stay in private evidence. Record hashes and decisions.

## Implemented installation path and validation requirements

1. Add a guard-install branch to the thin verified-bundle launcher. Use the
   existing Ansible playbook, never an unverified direct invocation. Freeze every
   script, template, policy, rendered rule, expected table digest and installation
   manifest produced by the freezer using `scripts/render_guard.py` for the isolated parser digest.
2. Replace caller assertions of qualification with independently checked baseline
   evidence. Validate the installed target parser and semantic table normalization;
   capture unrelated rules for comparison without restoring the whole ruleset.
3. Define numerical controller and node timeouts. The candidate timer is 300
   seconds; the controller must stop or recover before it expires. Verify timer
   arming before production artifacts are installed, and independent readback
   before acceptance/disarm. Do not restart user@999 or start Nautobot.
4. Close recovery evidence gaps: rollback now records `rolled_back` or `manual_intervention`. Record and independently
   verify removal, service enablement restoration, unchanged unrelated rules and
   preserved evidence. Handle failures before the install block without claiming
   rollback or acceptance. Stop/disarm recovery only after verified completion.
5. Test the launcher, failed parser validation, partial install, controller loss,
   acceptance/watchdog race, existing-file refusal, unrelated-rule preservation,
   listener-present refusal and successful cleanup. Reuse existing guard tests.

## Installation acceptance and recovery

Require matching installed file hashes, effective normalized table, enabled
persistence service, verified rootless startup ordering and read-only verifier
permission; prove TCP8080 still closed and management/monitoring still reachable.
Retain reboot persistence as untested until a separately authorized reboot.
A closed port cannot prove allowed/denied access: installation acceptance is not
backend packet qualification or permission to start the application.

On failure, run the staged `rollback_install.py` through the reviewed recovery
path. It refuses altered artifacts or any TCP8080 listener, removes only the
owned table/files and reloads systemd. Never flush or restore the full ruleset.
If safe removal cannot be proved, retain restrictive rules and report manual
recovery. Keep protected evidence and exact input hashes. Console access is the
fallback if SSH fails; do not reboot automatically.

## Separate packet and startup stages

After installation archival, prepare a bounded disposable listener operation.
Prove allowed traffic from each proxy over IPv4/ULA, denied traffic from the Munin
vantage with matching drop-counter deltas, healthy allowed probes bracketing each
negative test, and loopback recovery. Preserve SSH/Webmin/Munin; remove the listener
and verify closure. Actual Caddy traffic and reboot ordering remain later checks.
Only then hand accepted firewall evidence to Nautobot's separately approved startup
operation. No application, database or worker startup is included here.
