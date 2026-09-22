# Primary-node preferred-source route preparation

## Scope and status

Prepare one route on pihole0 (pi@10.1.0.53): destination
`fd36:5aa8:6971:1::170/128`, interface eth0, preferred source
`fd36:5aa8:6971:1::53`. Keep the same route approach and permanent-source allowlist.
The standby route is accepted; its terminal tag is
`nautobot-standby-route-accepted`. Publication is pending explicit public-destination
approval. No primary execution bundle is ready and no host was contacted for this
preparation. The consumed standby bundle must not be reused or edited.

## Proposed sequence

Keep this a one-node maintenance operation. Use the DNS owner's existing
[service-stop and delayed-failback procedure](../../../homelab-dns/Keepalived/docs/keepalived-dual-stack-runbook.md#phase-9-controlled-service-stop-failover)
to let the qualified standby carry DNS and proxy traffic while the primary route
changes. Do not redesign Caddy or change Keepalived priorities, addresses or health
thresholds. Because the cluster couples DNS and Caddy ownership, verify all four
VIPs (.55/.56 and ::55/::56), not just the DNS pair shown in the older runbook.

1. Read-only preflight on both nodes: capture boot IDs, active profile UUID/path,
   manager version, route and helper/state baseline, permanent addresses, HA
   configuration and current ownership. Recheck accepted standby source selection
   for Caddy's UID, both permanent-node families and cluster DNS/HTTPS service.
   Confirm console/physical recovery for the primary; the existing confirmation
   applies only to the standby. Resolve controller tools and certificate trust.
2. Bind a DNS-owner handoff and restoration step into the reviewed operation.
   Stop only primary Keepalived; prove all VIPs are served by pihole00 before any
   route write. Keep primary DNS/Caddy running. If the standby cannot serve, restore
   primary Keepalived and stop without changing its route.
3. With the primary no longer owning VIPs, preserve its exact profile, arm a local
   recovery watchdog and add/reapply the one route. Reuse the settled-route checks
   qualified on standby, plus 60-second node recovery and 60-second stable-service
   checks. Primary Keepalived is intentionally stopped in this phase; the collector
   must expect that instead of requiring BACKUP or four active services.
4. Restart primary Keepalived and observe the configured delayed failback. Verify
   both nodes, all four VIPs, the primary source for Caddy's UID before and after
   ownership returns, and continued sampled DNS/HTTPS service. Finish with the
   original primary/standby roles restored and 60 seconds of stable health.
5. Accept only the primary route. Preserve the exact execution definition and
   sanitized result before advancing to the target firewall operation.

Brief changed-node interruption remains permitted. Planned handoff/failback is
additional scope: the new bundle must explicitly authorize it and define bounded
handoff timing and how transition probe failures are assessed. Do not carry over
the standby runner's invariant that VIP ownership never changes, or silently accept
cluster service loss. Read the deployed health/preemption timing before choosing
those numeric limits; preparation does not invent observed values.

## Recovery and implementation work

The primary profile UUID, current route property and residue must be freshly
verified rather than copied from standby. Refuse conflicting destination routes
or unknown existing state. Archive any owned prior evidence before replacement.

The node watchdog must cover both route rollback and restarting primary Keepalived
if the controller disappears during handoff. It must be armed before stopping
Keepalived. Before the route changes, recovery only restores the original service
state. After a route write, restore exact profile bytes/metadata and the prior route,
then restore primary Keepalived. Preserve the accepted standby route throughout.
If recovery cannot be proved, stop for console recovery; do not modify the second
node or loop through repeated reapply/failover attempts.

Implement these phases in the existing Ansible/helper path, using explicit node
identity and expected role per phase. Add focused tests for failed handoff (no route
mutation), partial apply, controller loss, route rollback plus service restoration,
and failed failback. Do not relax the existing standby contract or patch its frozen
bundle. Freeze a new exact bundle only after these tests and preflight pass.

The immediate next live request is bounded read-only preflight on pi@10.1.0.53 and
pi@10.1.0.54 for the facts above. It makes no route/service/HA changes and does not
run self-tests or contact Nautobot storage. Live handoff and primary mutation need
their own exact-bundle authorization. No firewall, Caddy configuration publication,
application startup, reboot or package changes are included.
