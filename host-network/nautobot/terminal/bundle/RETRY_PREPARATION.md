# Route failure diagnosis and retry preparation

## Verified findings

The consumed first standby operation failed and restored its profile and routes.
Its frozen bundle and raw evidence remain unchanged. Follow-up read-only inspection
explains the dispatcher warning: the installed 01-ifupdown script rejects the
NetworkManager `reapply` event with exit 1. Its unknown-action branch does not run
ifupdown hooks. A local replay of the retained script reproduced that behavior;
no dispatcher or health script was executed on the live node during investigation.

The complete incident journal adds a material qualification to the earlier result:
Caddy's health check returned 21, Keepalived entered FAULT at 12:57:14 local time and
recovered to BACKUP at 12:57:22 on September 22. The installed health script assigns
21 to failure of its IPv6 HTTPS/204 check. All services being active afterward did
not establish uninterrupted HA health. The collected standby evidence does not
establish whether VIP ownership elsewhere changed. Do not claim HA continuity.

The journal shows NetworkManager reapply succeeded and IPv6 address activity during
the operation/rollback. The original failed route-get stderr was discarded. This
supports investigating asynchronous network convergence but does not prove the
precise route-get error or separate apply effects from rollback effects. Waiting
longer must not silently convert an HA interruption into acceptance.

The rollback service journal records execution at 13:02:09 and successful exit
at 13:02:10. Timer and service are now inactive/dead; service Result=success.
The protected state remains rolled_back. Helpers/policy and evidence remain.
Private evidence: /home/aaron/code/.local-evidence/nautobot-route-diagnostics-20260922.

## Repository correction

The reusable helper now retains command argv, exit status and timeout status.
Only bounded printable `ip` stderr is retained verbatim; non-ip stderr is suppressed
because it can contain profile content. It never records profile stdout in failure
messages. Settlement uses a 20-second monotonic deadline, at most 20 samples and
three consecutive source/address/DAD/owned-route matches. Individual real probes
are capped at two seconds and remaining deadline; malformed evidence fails
immediately. Samples are saved in protected operation state even on failure.

Local tests cover transient command failure followed by recovery, persistent wrong
source, malformed output, timeout diagnostics, non-ip redaction and refusal to
freeze another live bundle. Existing rollback and command-boundary tests remain.
No change has been applied to either proxy or dispatcher.

## Selected retry approach

On September 22 the user accepted brief, transitory node interruption provided the
cluster continues serving and the changed node recovers. Keep the existing
NetworkManager preferred-source route approach. No Caddy transport redesign or
dispatcher patch is needed for this retry. The prior eight-second FAULT interval
is retained as evidence; it is not by itself a reason to reject this approach.
Historical cluster continuity remains unproven and is not retroactively accepted.

Use one standby node per operation. Do not deliberately transfer VIPs, change the
primary or alter health-check thresholds. The following numerical bounds are implemented in the
retry contract and will be bound into the separately approved execution bundle:

1. Before mutation, verify the primary owns the expected VIPs, the target is
   BACKUP, both nodes are healthy and cluster DNS and HTTPS checks pass over IPv4
   and IPv6. Use existing known-good DNS answers and Caddy HTTPS health endpoints
   (HTTP 204), retaining their exact query/name/address inputs in the bundle.
2. From the controller, sample those cluster endpoints every five seconds with
   bounded probes throughout apply and recovery. Preserve errors and sampling gaps;
   do not call sampled success proof of zero packet loss. A failed cluster probe
   stops acceptance and invokes scoped rollback; do not proceed to another node.
3. Allow transient target health-check failure or FAULT during reapply. Require
   target SSH, both permanent-address DNS/HTTPS checks and BACKUP recovery within
   60 seconds from the pre-apply controller marker (a conservative bound). Retain the existing 20-second route-settlement check.
   Any route failure, recovery deadline breach, unexpected boot or VIP ownership
   change prevents acceptance and invokes rollback.
4. After recovery, require 60 seconds of passing cluster and target checks, correct
   source/route/address readback and no renewed FAULT. Review timestamped HA journal
   transitions rather than relying only on active daemon status. Keep the existing
   300-second rollback watchdog armed until all checks pass.
5. On rollback, verify the original profile/route and node recovery, plus cluster
   service health. If those cannot be established, stop with a manual-recovery
   result and use the confirmed console/physical recovery path. Do not repeat
   reapply indefinitely or mutate the primary to mask a failed standby operation.

## Remaining preparation

The availability decision is resolved. The executable retry and recovery checks are now
implemented and locally tested; live acceptance remains unproven.
The first-install launcher still correctly refuses the existing helper/state
residue. Preserve the consumed bundle, profile backup and terminal evidence before
reconciliation. Bind the expected retained helper/policy/state hashes, archive
those protected files before replacement, and handle the expired timer explicitly.
Do not overwrite unknown residue or reuse the consumed bundle.

`retry-contract.json` binds the consumed helper/policy hashes, observed rolled-back
state fields and restored profile path/hash. The raw state includes a private
profile backup: compare its approved fields and validate the backup bytes against
that profile hash, then hash/archive the complete raw state locally on the node.
Its opaque whole-file hash was not collected previously and is not invented.
Unknown files, symlinks, metadata drift and an existing archive stop reconciliation.
The archive is `/var/lib/nautobot-proxy-route-archive/<consumed-bundle-hash>`;
retained artifacts are never deleted. The retry uses
`nautobot-proxy-route-retry-rollback.timer` to avoid reusing the expired unit name.

The controller checks exact A `10.1.2.170` for
`j2-svpi4mf.local.theama.co` through DNS VIPs `.55`/`::55` and each node's
permanent address. HTTPS checks retain TLS verification and require HTTP 204:
`https://proxy.local.theama.co/` via proxy VIPs `.56`/`::56`, and
`https://pihole0.local.theama.co/healthz` or
`https://pihole00.local.theama.co/healthz` via each node's permanent addresses.
Parallel probes have a four-second outer limit and a five-second cadence;
a gap over eight seconds blocks acceptance. Strict SSH reads boot, addresses,
service status and the last coupled-group HA transition on both nodes. Primary
transition changes block acceptance even if it has already recovered. The final
stable interval must extend at least 60 seconds beyond apply completion.

If SSH becomes unreachable, Ansible rescue may not execute. The independent
node timer remains responsible for expiry rollback; controller interruption or
missing recovery evidence is reported as unverified, never accepted. Stop and
inspect the retained timer/state before any future retry.

The existing Ansible path implements these checks. Focused tests cover transient
recovery, persistent node failure, cluster probe failure, archive drift and rollback.
Freeze a new exact bundle for execution authorization. Primary changes,
intentional failover, target firewall and application startup remain later scopes.
No live change, retry, dispatcher edit, commit or push is part of this review.
