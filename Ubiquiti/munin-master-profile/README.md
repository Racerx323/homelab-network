# Munin master profile persistence

The later [static-network decision](../svmf-static-network-review.md) supersedes
preserving automatic addressing as desired state. This payload and its consumed
save remain historical; they must not be repurposed to deploy the static ULA.

The separately approved October 20 saved-profile inspection found the active
master Ethernet profile under `/run/NetworkManager/system-connections`, with
NetworkManager 1.42.4. The installed defaults support stable generation, but
that runtime keyfile alone does not establish a saved persistent profile.
The first inspection held at a restrictive path check; the corrected inspection
completed. Neither changed networking.

[persist.py](persist.py) proposes saving the current profile through native
NetworkManager while retaining its UUID and complete effective Ethernet,
connection, IPv4, IPv6 and proxy settings. Unsupported profile sections stop the
operation. It sets the already-effective connection name and default generation
values, with no activation, reapply, reload, renewal, restart or reboot.
It checks both exact route sources, active UUID, effective-setting fingerprints,
host-identity-file metadata and NetworkManager service identity before/after.

The NTP-owned controller transports this network-owned payload. Its
`master-profile-save` mode seals the payload/tests, controller/helper, review,
accepted runtime-profile inspection and pinned host key into one archive.
Prepare against the completed master-persistence inspection; live execution
requires its own exact archive SHA-256 approval. Preparation makes no contact.

An original runtime-profile backup remains root-private on the master. A failed
pre-write check submits no network write. A failure after write submission holds
with intent and backup retained; no delete, reload, reactivation or speculative
automatic restoration occurs. Inspect live state and approve a native settings
restoration separately if needed. The payload has parser/rejection and simulated backend success/drift tests.
The approved `munin-master-profile-save-20261020-v1` executed once on October 20
and passed native readback: root-owned mode-0600 persistent profile, same UUID
and effective settings, unchanged IPv4/ULA route sources, NetworkManager service
identity and host-identity-file metadata. The private backup is retained and
recovery was not needed. No connection reactivation occurred.

The accepted saved-policy readback qualifies configured persistence under
unchanged prefix, UUID and host identity. Actual renewal/reboot behavior remains
a checkpoint at the next separately approved master maintenance window in
OBS-07. Do not reboot the master merely to close an observation item.

## Static-address readiness inspection

[inspect.py](inspect.py) is the network-owned read-only collector for the new
static-address decision. It reads selected non-secret settings/runtime fields,
profile metadata, routes, passive neighbors, TCP listeners, service identities,
native device help and a typed projection of local firewall rules. It does not
read profile contents or host secrets, create a checkpoint, probe another host,
change settings, invoke containers or make an HTTP request. Missing tools and
unsupported firewall expressions remain findings; no address availability or
recovery capability is inferred from capture completion.

The NTP coordinator seals it with `--mode master-network-readiness` against the
accepted profile-save capture. The archive includes this collector, offline
tests, IPAM, the static-network review, helper/controller, baseline provenance
and pinned host key. Each execution needs that exact archive hash approval;
the earlier profile-save authorization cannot be reused. See the
[static-network review](../svmf-static-network-review.md) for remaining
controller conflict checks, backup, guarded activation and independent recovery.

The approved static-readiness inspection completed without mutation. Runtime
methods remain automatic, the desired ::83 ULA is absent, and selected settings
and NetworkManager identity stayed unchanged. Native help stdout was empty;
that first capture did not establish checkpoint support. Passive neighbors and
the partial firewall projection do not establish address availability or access.
The later recovery and controller reviews have now completed without mutation.
No dashboard or container-health test was performed.

`--mode master-recovery-readiness` prepares a host-local inspection against
that completed readiness capture. It reads checkpoint excerpts from both native
help streams and the protected installed nmcli manual, with expansion/output
bounds and unchanged host/boot/UUID/NetworkManager checks. It does not create a
checkpoint, exercise rollback or establish independent recovery access. The
network-owned collector/tests remain sealed with the NTP coordinator.

The accepted recovery capture found checkpoint syntax and timeout/confirmation
behavior in the protected installed nmcli 1.42.4 manual. This is documentation
qualification, not an exercised checkpoint/rollback. The operator confirms local
console availability. Settings and local guarded recovery qualification have
subsequently been completed; controller collections reported no conflict but exposed no selected
IPv6 fields, so DAD and guarded acceptance remain necessary. Do not replay either
consumed inspection.

## Finalized settings and native guard

[static-settings.json](static-settings.json) fixes IPv4 and the ULA while retaining
RA global IPv6/default routes, as selected by the operator. Both DNS VIPs and
search configuration are explicit. IPAM keeps these settings pending live
acceptance. The existing generated ULA is retained for transition consumers.

[guard.py](guard.py) is a reusable native checkpoint primitive, not a production
installer. [Offline tests](test_guard.py) cover ownership, mandatory guard before
write, full confirmation, expiry and saved-settings restoration. Native
[test fixture](test_native_rollback.py) requires an isolated systemd container
with NetworkManager 1.42.4, virtual DHCP/RA router and no host network. Use Podman
with the [Containerfile](Containerfile.rollback); pin actual image/source hashes
and capture all logs privately. The rootless fixture needs NET_ADMIN, NET_RAW,
SYS_ADMIN and private procfs access for its own router namespace. Never run the
fixture or its networking commands on a production host.

[Independent readback](verify_native_recovery.py) checks restored addresses,
route sources, RA default route, DNS and real peer reachability in retained
rollback fixtures. See the [execution review](../svmf-static-network-review.md)
for the production wrapper and live acceptance gates.

## Production wrapper

[deploy.py](deploy.py) supplies a sealed, single-use production entrypoint around
the native primitive. Its detached root systemd worker owns exact backup/durable
state, identity/full-effective-profile validation, activation, resolver/application
gates, independent fresh dual-stack SSH confirmation and held recovery. The
controller retains private transport receipts; a separate read-only continuation
inspects interrupted operations without replay or restoration. Follow the
[runbook](../svmf-network-deployment.md) for sealing, execution and console holds.

[Offline contracts](test_deploy.py) cover the worker/controller boundaries and run
in pre-commit/CI. The actual [wrapper fixture](test_native_deploy.py) uses real
SSH, systemd and NetworkManager with a private DHCP/RA/DNS router and synthetic
[applications](fixture_apps.py); build its [image](Containerfile.deploy) only after
recording the base native-image identity. Seven scenarios passed with the current
deployment/helper/settings bytes: commit, controller loss, worker loss,
failed health, foreign drift, interruption after the saved-profile write and
missing-AAAA rejection of mapped IPv4 before any checkpoint or profile mutation.
All five recovery paths have independent peer SSH/readback evidence. Held and
interrupted durable states remain unaccepted even when networking recovers.

The local fixture is Debian 12 amd64/NetworkManager 1.42.4. It does not establish
live ARM64, production DAD, actual application/resolver continuity, console
restoration or reboot persistence. Host execution requires its own sealed-hash
approval. NTP DNS prerequisites precede the network successor; Munin/svmf DNS
and monitoring follow accepted host networking.

## Dashboard preflight metadata diagnostic

The successor wrapper now requires the accepted Apache deployment as an explicit
`--dashboard-baseline`. It pins the public CA snapshot and this repository's
HTTPS helper, requires root/CSS/PNG over literal destinations with fixed
SNI/hostname/Host, and validates all three responses in both confirmation proofs.
The earlier HTTPS-only successor was sealed as `svmf-static-network-20261020-v2`, archive SHA-256
`20e8297328c270b3c623076479ae6feb35f5f855bfc3e49e44c531f99fb8de83`,
after 17 offline contracts and all six native scenarios passed with its bytes.
No production contact occurred during this requalification or preparation.
Its later approved execution stopped at preflight on the incorrect ntp2 lookup.
That archive is consumed and immutable. The current repository correction passed
21 offline contracts and seven native cases, but is not sealed for production;
accept the separate NTP DNS prerequisite and refresh baseline requirements first.
The network checkpoint, full-file validation, 25-second network freshness,
exclusive receipts and held-recovery controls are unchanged. Its
[native orchestrator](run_native_https.py) retains isolated HTTPS fixture results
and refuses to reuse an evidence revision. The old executed HTTP-only archives
remain immutable and cannot authorize a successor execution.

The authorized production v1 controller stopped at its first HTTP check before
SSH or host mutation. It retained a generic failure label without the status or
body-size distinction. Its execution receipt is consumed; do not replay it.
[probe_dashboard.py](probe_dashboard.py) seals a separate bounded read-only review
using the failed bundle's original endpoint data. Its execution makes one GET
through each original address at the same HTTP path/Host; it records status and
redacted metadata without response bodies, redirects, credentials or SSH.
[Tests](test_probe_dashboard.py) cover response classification, redaction, exact
scope, archive integrity/expiry and single-use receipts. The prepared diagnostic
requires its own hash-bound approval before contact; it does not install or fix
host networking, HTTP service bindings or DNS.

## Apache and verified HTTPS qualification

[qualify_dashboard.py](qualify_dashboard.py) seals a separate single-use review
with the pinned SSH key, public controller trust store, supplied vhost candidate
and [Apache reader](inspect_apache.py). One SSH session reads service identity,
listeners, parsed vhosts/modules/includes, selected directives and public
certificate metadata. It does not edit configuration, restart Apache or retrieve
private keys. Disk parsing cannot prove which bytes the running daemon loaded.

Through each original literal destination, HTTPS uses the dashboard hostname for
SNI, certificate verification and Host. It never follows redirects or disables
verification. At most seven GETs per family cover root, `/munin/`, bounded linked
HTML discovery, one stylesheet and one daily PNG. A failed initial TLS handshake
stops that family. Bodies stay in memory; evidence retains status, TLS/source
identity and size/hash metadata. Requests can cause ordinary access logs and CGI
cache generation. Sampled access does not establish graph freshness or access
from every management client. [Offline tests](test_qualify_dashboard.py) cover
trust/identity, discovery bounds, response classification, config filtering,
archive integrity and replay rejection. Live execution requires the new archive's
exact hash approval; no existing receipt can be reused.

## Targeted graph discovery

The Apache/TLS capture verified root/HTML and TLS over both original address
families but found `/munin/` forbidden on both and stylesheet denial over IPv6.
Its broad traversal sampled sibling domain indexes and found no daily graph.
[qualify_graph.py](qualify_graph.py) seals a new read-only stage starting from
the observed `/J1-SVMF/index.html`. It descends links under that master domain
before siblings, with at most four HTML reads, one stylesheet and one daily PNG
per family. It retains eligible link paths as bounded metadata to make any
remaining discovery gap inspectable. Bodies are not retained.

The new archive pins this repository's HTTPS helper and tests, public trust
snapshot and prior-capture provenance. It does not import implementations from
the prior archive. No SSH or new host configuration read is included. TLS,
literal endpoints, SNI/hostname/Host, response bounds and no-redirect behavior
remain enforced. [Seven tests](test_qualify_graph.py) cover descent, bounds,
scope, archive integrity, frozen helper and replay. The old consumed archive
cannot authorize this new stage. The Apache owner separately prepares the
[IPv6 access proposal](../../../homelab-monitoring-observability/Apache2/docs/munin-ipv6-access-review.md);
no Apache mutation is part of graph qualification.

## Retained preflight failure diagnostic

`diagnose_preflight.py` seals and executes a single-use read-only capture for the
consumed static-network v2 operation. It reads selected retained failure fields,
profile hash/metadata and unit status through one pinned IPv4 SSH session, with
host/boot/interface/UUID and manager continuity checks. Profile bytes stay on the
host. It cannot run the deployment worker or change network settings. Prepare
with `seal --baseline FAILED_BUNDLE --output NEW_PRIVATE_DIRECTORY`; approve the
resulting archive hash before `execute --directory OUTPUT --sha256 HASH`.
`test_diagnose_preflight.py` checks filtering, identity/integrity rejection,
single-session scope and receipt consumption after success or timeout.

Use `diagnose_preflight.py seal --resolver --baseline FAILED_BUNDLE --output NEW_PRIVATE_DIRECTORY`
for the separate resolver/NSS scope. This freezes the corrected ntp1 lookup name,
separate family status/results and selected hosts/resolver/runtime DNS fields;
optional dig queries cover A/AAAA through the two fixed DNS VIPs. Its exact-hash
execution approval is separate. Negative results are diagnostic evidence; neither
capture completion nor the synthetic fixture accepts production DNS readiness.

The production wrapper now pins `ntp1.local.theama.co` and the exact native .51
and ::51 endpoints. It rejects mapped IPv4, wrong-family, empty and extra/wrong
addresses both when collecting a snapshot and when checking an independent
observation. Lookup failures identify their family and retain exit/bound/timeout
details. Existing executed bundles remain immutable. The missing-AAAA native
fixture reproduces successful ahostsv6 mapped fallback and requires rejection
before checkpoint, backup or profile mutation, followed by independent original-
family SSH/HTTPS checks after restoring only the synthetic DNS fixture.
