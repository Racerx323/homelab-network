# svmf static host network review

Finalized settings and a locally qualified production wrapper. The authorized
v1 controller stopped at the initial HTTP gate before SSH or host mutation; its
approval is consumed. The approved metadata diagnostic then observed HTTP 301
to HTTPS through both original address families. Subsequent qualification passed
TLS/root HTML on both, but found IPv6 stylesheet denial and no usable `/munin/`
route. Targeted graph qualification then passed sampled CSS/PNG over IPv4 but
found IPv6 403 for both. The approved Apache ACL transaction has now committed;
verified HTTPS root/CSS/PNG pass on both original families. The corrected-name HTTPS network
successor committed October 21; separate Munin/svmf DNS review is next.
The static allocation supersedes the earlier automatic-address preservation decision. The accepted profile save
remains historical evidence; it did not assign the new ULA or static IPv4.

## Current checkpoint — October 21, 2026

The NTP-only DNS prerequisite has now executed and passed on both nodes under
archive SHA-256 `54224a0beac93bc715a8af42ce39b673a7b14f18ac300e1524f714364f03d545`.
Both ntp1 AAAA ::51 and canonical IPv6 PTR are served; A/IPv4 PTR and unrelated
checks passed. DNS/Caddy service and TLS health passed with all four linked VIPs
on .53 in retained samples. No forced failover or proxy configuration change occurred.
The [accepted DNS outcome](../../homelab-dns/Unbound/docs/ntp1-ipv6-prerequisite-review.md#deployment-accepted--october-21-2026)
records consumed phases and retained backups.

The successor `svmf-network-static-20261021-v1` executed once and committed
October 21 at 09:58:00 CDT under archive
`935f60fd1dab11fa3a209efb98be40b3657143c2b9148065a8640db0ac160b8e`.
The [accepted outcome](/home/aaron/code/.local-evidence/homelab-network/current/svmf-static-network-20261021-v1/outcome.md) records
static .83/::83, DAD, selected NTP route sources, native ntp1 .51/::51,
DNS/search and service continuity. Independent SSH and verified Munin HTTPS
root/CSS/sample PNG passed both intended literal families after commit.
RA/global routing and the generated ULA were retained. No rollback or reboot;
physical reboot/renewal persistence and graph freshness remain unobserved.
Backup/state remain under the operation directory; the receipt is consumed.
The separate [Munin/svmf DNS outcome](/home/aaron/code/.local-evidence/homelab-dns/current/munin-svmf-dns-deployment-20261021-v1/outcome.md)
passed October 21 at 10:12:30 CDT under archive
`81d6544c533baa2592c9e63c093f2be2f403400309ffc244fb0561840a827e30`: both AAAA records and the
canonical IPv6 PTR are accepted with paired DNS/Caddy health. All five phases
are consumed; backups remain. Next reconcile and finish separate monitoring
node installation, job-success recording and master acceptance reviews.
Client refresh, graph freshness, alert delivery and physical persistence remain
open; no further live probes or cleanup followed accepted execution.

## Desired state and boundaries

The network owner allocates `10.1.3.83/22` and
`fd36:5aa8:6971:1::83/64` as static host addresses on the master's `eth0`.
See [IPAM](../ipam/README.md). Keep the existing IPv4 reservation to prevent
another DHCP client receiving that address. Use the existing profile UUID
after revalidating it; do not create competing autoconnect profiles.

The finalized [settings](munin-master-profile/static-settings.json) use manual
IPv4 `10.1.3.83/22`, gateway `10.1.0.1`, DNS `10.1.0.55` and search domain
`local.theama.co`. IPv6 retains method `auto` for RA-provided global addresses
and routes, with explicit static ULA `fd36:5aa8:6971:1::83/64` added to the saved
profile. The operator selected this combined mode. An empty explicit IPv6 gateway
preserves the RA default route; do not pin the observed router link-local address.
Keep the existing generated ULA for existing consumers during transition.

Pin IPv6 DNS to `fd36:5aa8:6971:1::55` and reject automatic DNS in both families;
these are the observed DNS VIPs. Preserve autoconnect and address-generation
identity. Require actual route-source readback selecting ::83 for the NTP node;
retaining RA must not silently accept polling from the old generated ULA.
Both methods must succeed; static ULA DAD must complete without tentative/failed
flags. Do not disable working global IPv6 or remove unrelated routes.

This host also serves Mailrise/Apprise and the native Munin master. Inventory
names elsewhere are not proof of additional hosts or permission to rename them.
Do not modify UniFi, DNS, firewall, containers, alert contacts or service bindings
inside this host-network stage. Each owner accepts its changes separately.

## Required read-only readiness capture

Prepare and approve a separate hash-bound inspection of `pi@10.1.3.83`, strict
host-key alias `svmf.local.theama.co`, before any target contact. Pin host/boot,
active profile UUID and NetworkManager version. Capture only selected non-secret
fields: profile filename/metadata, methods, addresses, routes, gateways, resolver
settings, autoconnect and privacy/source-generation policy. Record effective
IPv4/IPv6 addresses, routes to both fixed NTP addresses, actual selected sources,
DNS configuration, listeners and relevant firewall rules. Do not read secrets or
export unrestricted profile/container configuration.

Verify the installed checkpoint/rollback capability and recovery access. Establish
an exact private backup and a timed native rollback path before reactivation.
Check IPAM/controller assignments and neighbor observations for conflicts with
`::83`; silence alone does not prove an address is unused. Mutation-time DAD
must complete successfully. Record shared service health and affected consumers.
The current generated ULA must not be removed until dependent allowlists/bindings
are identified and the transition is explicitly reviewed.

## Mutation, acceptance and recovery to seal

Bind the observed profile, exact settings, backup, checkpoint timeout, mutation
and reactivation commands, health checks and rollback commands in one network-owned
execution bundle. Saving settings alone cannot prove active static networking.
Activation may interrupt SSH; use a verified recovery channel and native timed
rollback rather than assuming the controller can reconnect.

Require saved and active static IPv4/ULA readback, unchanged intended routes/DNS,
successful DAD, independent fresh SSH over both literal addresses and route-source
selection to `10.1.0.51` and `fd36:5aa8:6971:1::51` from the allocated addresses.
Preserve the master scheduler and existing Mailrise/Apprise service health.
Accept only after the bounded convergence window; cancel the checkpoint only
after all gates pass. Do not reboot as part of this scope.

On failure restore only the exact original profile through the qualified native
checkpoint/backup path, then prove original settings, sources and service health.
Foreign profile drift or unverifiable recovery holds for manual intervention.
Retain backups and both failure/recovery evidence. Do not advance DNS publication
or Munin allowlists while the intended static network state is unaccepted.

## Handoff

After network acceptance, the DNS owner deploys both forward AAAA records and one
canonical IPv6 PTR. The monitoring owner separately validates dashboard listeners
and master polling over both families. Future renewal/reboot observation compares
the accepted static configuration; it must not restore the old generated ULA as
the desired identity.

## Qualified guard and production execution gates

[guard.py](munin-master-profile/guard.py) uses NetworkManager's native D-Bus
checkpoint for exactly one device and the existing UUID. It rejects competing
checkpoints before writing, verifies persisted settings and requires complete
acceptance before destroying only its own checkpoint. The actual helper and
settings are exercised under NetworkManager 1.42.4 in an isolated Debian 12
amd64 systemd fixture, with a private DHCP/RA router and independent peer.
Coverage includes commit, explicit rollback, timeout, actual controller-process
exit, failed acceptance and interruption after a saved-profile write. Independent
post-terminal readback covers original saved settings, active addresses, routes,
DNS and peer reachability. Retain exact input hashes and outcomes in history and
private evidence. This is native-mechanism qualification, not ARM64 or live-host
acceptance.

The helper remains a library. The [production wrapper](munin-master-profile/deploy.py)
and [runbook](svmf-network-deployment.md) implement the outer operation that:

1. Pins accepted host/boot/MAC/UUID, installed version, source bytes, complete
   original settings/profile metadata and exact non-secret execution inputs;
   obtains root-private exact profile backup and records state durably before
   creating a 300-second native checkpoint. No existing checkpoint may be erased.
2. Changes only the finalized settings on the same profile and activates it.
   Verify static addresses, completed DAD, retained RA/global IPv6/default route,
   exact DNS/search configuration and expected NTP route sources. Preserve
   unrelated profile fields and existing generated ULA consumers.
3. Reconnects independently over both literal management addresses using the
   accepted host key. Compare the before/after Apache/cron/SSH/Munin service
   identities and existing application endpoints. Package, DNS, firewall and
   container changes are outside this stage. Fixture NetworkManager continuity
   does not establish production application or resolver continuity.
4. Rechecks all gates and the owned checkpoint with a bounded confirmation
   reserve before explicit commit. If connectivity/gates fail, do not confirm;
   native timeout restores the original saved/active configuration. On caught
   failure request rollback only for the owned checkpoint and independently
   verify original addressing, routes, resolver behavior, services and access.
5. On interruption inspect retained state before any continuation. Never replay
   apply, clear every checkpoint or infer recovery from API success. Retain exact
   backup and operator console recovery procedure for a daemon crash or failure
   outside the native checkpoint's lifetime. The native guard is not claimed
   to survive NetworkManager restart or reboot. Neither is authorized here.

The wrapper uses a detached root systemd supervisor, exclusive local/target
receipts, exact fsynced backup and durable state, expiring sealed inputs and
fresh pinned-key SSH over both fixed addresses. Confirmation is submitted once;
interrupted operations expose a separate read-only continuation and cannot replay.
The before/after checks include actual resolver configuration/results, core
service identities, Apprise HTTP status and a Mailrise greeting/QUIT exchange.
No notification is sent. The strict candidate Munin dashboard path is a reviewed
precondition; an absent or authenticated path stops the controller before staging.

The legacy HTTP-only qualification had fifteen offline contracts and six native
scenarios. The HTTPS successor now has seventeen offline contracts and six real
isolated scenarios passing with its exact deployment/helper/guard/settings bytes.
Five recovery paths have original-family SSH and three-asset HTTPS evidence.
Checkpoint and settings bytes are unchanged. The consumed v1 and its
`svmf-wrapper-qualification-20261020-v1` witnesses remain archival; successor
witnesses are in `svmf-https-wrapper-qualification-20261020-v1`. This is local
qualification, not live ARM64, production resolver/application, DAD or console
acceptance. Worker loss leaves the native timer armed; failed health or foreign
drift must remain held even if networking later recovers. Keep exact source
hashes with the review. Local console is operator-confirmed; console recovery
and production network rollback have not been exercised.
The controller's limited IPv6 visibility does not waive mutation-time DAD.

## Consumed v1 and current diagnostic gate

The approved `svmf-static-network-20261020-v1` controller was executed once and
stopped at its initial IPv4 dashboard check before SSH. Its retained generic
`HTTP health failed` label does not distinguish response status, empty body or
oversized body. No target staging, checkpoint or profile write was attempted by
this operation; do not infer otherwise-current host state. The consumed archive
and execution receipts are preserved and must not replay.

The approved `svmf-dashboard-inspection-20261020-v1` ran once using the
repository-owned [reader](munin-master-profile/probe_dashboard.py). Both original
literal addresses returned HTTP 301 to HTTPS at `munin.local.theama.co/munin/`;
bodies were nonempty and within the gate's size limit. The consumed controller
required HTTP 200. The diagnostic retained redacted metadata only and did not
follow the redirect, contact HTTPS/SSH or change host configuration. Its receipt
is also consumed. The old run's actual status was not retained; these responses
are subsequent observations.

The operator identifies Apache as the server and moved the supplied configuration
into the [repository vhost](../../homelab-monitoring-observability/Apache2/configs/001-munin.theama.co-ssl.conf).
At capture, the supplied bytes matched the frozen qualification candidate and
enabled vhost on disk. Its ServerName and explicit port-80
HTTPS redirect match these observations. Captured `Require ip` lists contain
RFC1918 IPv4 ranges and `::1`, with no ULA client range. Disk equivalence does not
prove which bytes the running process loaded. Root-page rewrites coexist with
`/munin/` handling; observed request results now distinguish those paths.

Executed `svmf-apache-qualification-20261020-v1` once, archive SHA-256
`87ba990d3cdbc21321f8aabfec18ea0e5549eaf985af7c4a81318ae0cc1f8ed2`,
using the repository-owned [qualifier](munin-master-profile/qualify_dashboard.py)
and [reader](munin-master-profile/inspect_apache.py). They performed one SSH collection
and twelve verified HTTPS GETs. TLSv1.3 and certificate validation passed on both
original families. Apache owns TCP 80/443 and its service identity stayed stable.
Root and three discovered HTML pages returned 200 on both families; `/munin/`
returned 403 on both. `/static/style-new.css` returned IPv4 200 and IPv6 403.
The latter is consistent with the missing ULA ACL; exact merging remains untraced.
No daily graph link was discovered within the approved traversal, and no PNG was
requested. The receipt is consumed. No administrative configuration or service
change occurred; normal request logs and CGI caches may have been written.

Executed targeted graph qualification `svmf-graph-qualification-20261020-v1`,
archive SHA-256 `f183d89b85872fe132a921043a7870731c1044cf1948bc5278fae9b4a246dbd8`,
once after exact-hash approval. Eight GETs verified TLS throughout. Two HTML
pages returned 200 on both families; the sampled stylesheet and discovered daily
graph returned IPv4 200 and IPv6 403. The IPv4 graph had the expected content type
and PNG signature. Its exact discovered path is
`/munin-cgi/munin-cgi-graph/J1-SVMF/J1-SVMF/apache_accesses-day.png`.
No SSH, configuration change or service action occurred. Its receipt is consumed;
graph freshness is not established. The Apache owner's
[IPv6 access review](../../homelab-monitoring-observability/Apache2/docs/munin-ipv6-access-review.md)
defines four ULA ACL additions over that original captured baseline. Their
subsequent deployment is accepted below.

The Apache owner qualified configuration testing, graceful reload and restoration:
eight offline contracts, eight native transaction cases and an actual invalid
configuration/graceful-rejection check passed with Apache 2.4.68. The
[deployment workflow](../../homelab-monitoring-observability/Apache2/docs/acl-deployment.md)
is sealed as `svmf-apache-acl-20261020-v1`, archive SHA-256
`23aafda870c8cf1dc9863c48c5402ed8aa8306a06838c5d081f40760e0800941`.
No production contact occurred during qualification. The subsequently approved
live execution committed, with accepted target hash
`555551c423e879d6b0ea5706807f5bb7a02c6238293e7509527ecf6d2004091f`.
Final root/stylesheet/PNG responses were verified HTTPS 200 on both original
families, with expected types and PNG signature. Apache identity and root:root
0644 metadata were preserved. Original backup/state remain; restoration was not
needed. Its receipt is consumed, and the later guard no-op is not observed.

The successor wrapper has been updated/requalified and sealed as
`svmf-static-network-20261020-v2`, archive SHA-256
`20e8297328c270b3c623076479ae6feb35f5f855bfc3e49e44c531f99fb8de83`.
Its manifest pins the accepted Apache result, final six responses, CA snapshot
and current repository HTTPS helper. Seventeen offline contracts and all six
native scenarios passed; no new production contact occurred. Native witness
records are retained under `svmf-https-wrapper-qualification-20261020-v1`.

The approved v2 executed once on October 20, 2026. All six original-family
HTTPS baseline responses passed and pinned SSH staging succeeded. The detached
worker returned `preflight_failed` (controller exit 2), before checkpoint arming
or network-settings mutation. Remote staging and transient-unit execution occurred;
no rollback was invoked. The status response omits the failed predicate, so its
specific cause remains unknown. Private outcome/controller/transport evidence and
target staging are retained. v2 is consumed and cannot replay.

Next: prepare a scoped read-only diagnostic of retained worker state to identify
the failed predicate before preparing a successor. The interruption-only inspection
allowance is not used for this terminal failure. IPAM remains desired/pending;
DNS and NTP monitoring remain gated on accepted host networking. Preserve
SNI/hostname/Host verification and all qualified checkpoint/recovery controls.

## Prepared retained-state diagnostic

Prepared `svmf-preflight-diagnostic-20261020-v1`, archive SHA-256
`de3a3f8cf44801ca8dbe43a30b6ec05308fb246d16498a26849b36810889637e`.
The repository diagnostic and six offline contracts qualify one pinned IPv4 SSH
capture of retained failure fields, specification identity, profile hash/metadata
and selected service status. No profile contents are exported; no deployment
code runs remotely. Preparation contacted no target. Target execution awaits
approval of this diagnostic hash at preparation; execution subsequently completed
as recorded below. The consumed v2 cannot replay.

## Retained preflight diagnostic executed

Approved diagnostic `svmf-preflight-diagnostic-20261020-v1` executed once on
October 20, 2026 under the hash above. Capture completed without target mutation.
The retained failure is `RuntimeError: bounded command failed: getent` during
preflight. The label does not identify the family or distinguish nonzero exit
from exceeded output limits. It does not prove a DNS outage or NSS defect.
Profile content and all pinned metadata match the baseline; NetworkManager
identity stayed stable during capture. Successful worker service exit does not
override its durable `preflight_failed` state. The diagnostic receipt is consumed.

Next: prepare a scoped read-only resolver/NSS diagnostic for separate-family
lookup status/results, selected hosts policy and resolver configuration before
any correction or successor. Static networking, DNS publication and Munin remain
held. The readiness checklist owns this next gate.

## Corrected resolver diagnostic scope

The operator confirms ntp2 does not exist. The sealer hardcodes that incorrect
name, also used by the synthetic fixture. The governing plan/DNS repository
identify ntp1.local.theama.co at 10.1.0.51, with planned ::51 IPv6; the inspected
zone file lacks the corresponding AAAA. Current served records remain unverified.
Do not create ntp2 or weaken the dual-stack gate. The operator's bare getent
commands on j2-svntp1 did not reproduce a named svmf lookup.

Prepared `svmf-resolver-diagnostic-20261020-v1`, archive SHA-256
`12b1bb0a770ab96b541049550b7fe7feaaa8c121713c053cdf6aa2bd9ce34b0a`.
One pinned IPv4 SSH session captures both named ntp1 getent families, selected
NSS/resolver/runtime DNS data and four optional fixed-VIP A/AAAA queries. Ten
offline contracts passed; preparation contacted no target. Execution awaits
approval of this new hash. After findings, correct and qualify the repository
sealer and separately address any DNS prerequisites before a successor deployment.
Consumed production artifacts remain unchanged; all deployment holds remain.

## Resolver diagnostic executed: native IPv6 DNS prerequisite open

Approved `svmf-resolver-diagnostic-20261020-v1` executed once on October 20, 2026
under the hash above. Capture completed without target mutation. Both fixed DNS
VIP queries returned A 10.1.0.51 for ntp1 and NOERROR with zero AAAA answers.
Named ahostsv6 exited 0 but returned only mapped IPv4 ::ffff:10.1.0.51; native
::51 was absent. Runtime DNS matched the two VIPs, and selected files/manager
identity stayed stable. This does not inspect both physical DNS nodes or prove
the old wrong-name failure's exact family/status. The diagnostic is consumed.

Next: prepare a DNS-owner ntp1 AAAA/canonical IPv6 PTR prerequisite review with
fresh target/node readiness and serial HA validation. Correct/qualify the sealer
name, require the expected native family/address, reject mapped IPv4 as IPv6
proof and retain family-specific command failures before a network successor.
No DNS or wrapper change occurred under this diagnostic. Munin/svmf AAAA/PTR
remains a separate later change gated on accepted static host networking.

## Correct-name/native-family successor qualification completed

The repository wrapper now seals only ntp1.local.theama.co and its exact native
.51/::51 endpoints. It rejects mapped IPv4, wrong-family, empty, extra and wrong
addresses during snapshots and independent checks. Family-specific errors retain
exit status/output byte counts or timeout without raw stderr. Existing network
checkpoint, backup, full-file, freshness and recovery controls are unchanged.

Twenty-one offline contracts and seven native systemd/SSH/NetworkManager 1.42.4
cases passed with unchanged current candidate bytes. Commit and five recovery
paths preserved exact-backup, independent original-family SSH/HTTPS and durable
hold/incomplete-state boundaries. The missing-AAAA fixture reproduced successful
mapped fallback and failed before checkpoint, backup or profile mutation; after
restoring synthetic DNS, fresh original-family SSH/HTTPS confirmed the untouched
network. Initial name-collision launches never reached tests and are preserved;
the six unstarted cases passed as r2, while missing-aaaa-r1 was retained.
Private evidence: `svmf-resolver-wrapper-qualification-20261020-v1`.

The DNS owner's [NTP prerequisite review](../../homelab-dns/Unbound/docs/ntp1-ipv6-prerequisite-review.md)
and two pending record additions are prepared; fifteen repository DNS tests passed.
Both DNS nodes subsequently passed installed native candidate validation. Next:
qualify reload/full-restart and synchronization paths read-only, then accept a
separately approved NTP-only serial HA DNS deployment. Only afterward refresh
successor baselines and seal a new network operation. No new production contact
or deployment occurred here. Munin/svmf DNS and monitoring remain later gates;
ongoing maintenance/monitoring remains tracked in the consumer readiness checklist.

## Read-only NTP/DNS prerequisite inspections sealed

The DNS owner prepared separately hash-bound NTP-address, DNS .53 and DNS .54
inspection reviews on October 20, 2026. Seventeen offline contracts passed without
production contact. The consumer
[readiness checklist](../../homelab-ntp/ntpsec/docs/PRODUCTION-READINESS.md)
records all three archive hashes and their private review locations. All three
approved inspections subsequently executed once with complete captures and no
target mutation; receipts are consumed. NTP fixed-ULA/address identity passed.
Both DNS validators accepted the two-record in-memory candidate. Both VIPs stayed
on .53; .54 owned neither. AAAA and IPv6 PTR remain absent at every sampled path.

Before sealing DNS deployment, prepare scoped read-only qualification of the
actual Unbound reload, full Pi-hole restart and synchronization-writer paths.
The [local-zone guide](../../homelab-dns/Unbound/docs/Pi-hole-with-Unbound-local-zone-guide.md)
documents reload followed by full restart, including rollback, but installed
implementation and serial-change isolation remain unproven. Active Gravity Sync
timers and incomplete protected-file/writer projections remain explicit holds.
The corrected wrapper qualification is retained; first accept NTP-only DNS,
then refresh successor baselines and seal a new network operation. No consumed
readiness or network approval authorizes another live action.

## DNS control/writer follow-up prepared

The DNS owner has sealed separate read-only .53/.54 control and synchronization
qualification reviews; [the prerequisite review](../../homelab-dns/Unbound/docs/ntp1-ipv6-prerequisite-review.md#reloadrestart-and-synchronization-qualification-sealed)
records exact hashes and scope. Twenty-three offline contracts passed without
target contact. Execute only after each exact-hash approval, reconcile both
outcomes, close control/writer gaps and separately accept NTP-only DNS before
refreshing network baselines. No successor network deployment is sealed.

Both approved DNS control-qualification v1 captures subsequently stopped at the
protected unbound-control binary read; SSH/pinned identities passed but the
control/source/sync stage and final checks were not reached. No mutation occurred;
both receipts are consumed. The DNS owner sealed corrected v2 reviews with
unavailable-input handling, safe metadata and a passing regression. New exact-hash
approvals remain required before contact. DNS and network deployment stay held.

## DNS control qualification v2 captured

Both approved v2 inspections completed once without mutation; .53 retained both
DNS VIPs and .54 owned neither, with stable host/service identities. Plain
Pi-hole restartdns's source selects a full restart; Unbound unit HUP reload is
distinct from the owner's unbound-control path. Active Gravity Sync timers
select smart sync and source can push/pull/restart FTL. Effective overrides,
rejected config/crontab paths and complete Caddy writer scope remain unresolved.
Prepare the scoped read-only follow-up in the
[DNS prerequisite review](../../homelab-dns/Unbound/docs/ntp1-ipv6-prerequisite-review.md#control-qualification-v2-executed--remaining-isolation-gate).
Both receipts are consumed; no network successor or DNS deployment is accepted.

## Operator clarification supersedes sync/reload prerequisite

Unbound local-zone synchronization is not implemented; Caddy replication is
separate. The DNS owner will update nodes independently by atomic replacement,
validate, fully restart Unbound, establish its health and fully restart Pi-hole
DNS. Atomic rollback also requires both full restarts. Permit bounded coherent
cluster-driven failover while the other node serves; no forced VIP changes.
The next DNS gate is production transaction/recovery qualification and a new
sealed NTP-only deployment review, not broad sync or reload-path inspection.
The svmf network successor still follows accepted NTP DNS. No live action occurred.

## Atomic DNS transaction locally qualified

The DNS-owned successor passed 29 offline contracts and four isolated native
Unbound/systemd scenarios for atomic writes, full restarts, coherent VIP movement
and recovery. [The qualification report](../../homelab-dns/Unbound/docs/zone-transaction-qualification.md)
retains FTL/Keepalived/transport fixture limits. Next prepare the sealed NTP-only
DNS deployment review and obtain its exact-hash approval; no production contact
or new network bundle occurred. Accepted live NTP DNS still precedes refreshing
and sealing the svmf network successor.

## NTP-only DNS execution review sealed

The DNS owner prepared `ntp1-dns-deployment-20261020-v1`, archive SHA-256
`54224a0beac93bc715a8af42ce39b673a7b14f18ac300e1524f714364f03d545`.
Exact-hash execution approval is next. DNS .55/::55 and Proxy .56/::56 are coupled
under PIHOLE_DUALSTACK; Caddy can fail over with DNS. Brief read-only linked
ownership/service/HTTPS acceptance is included, without Caddy/Keepalived changes
or more fixtures/stand-in testing. No target contact occurred during sealing.
Live NTP DNS acceptance still precedes the svmf network successor.
