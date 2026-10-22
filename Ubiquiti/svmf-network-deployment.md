# svmf guarded network deployment

The repository-owned [wrapper](munin-master-profile/deploy.py) seals, executes
and inspects one host-network operation. Preparing a bundle and running isolated
tests do not authorize production contact. Execute only the approved bundle hash.
The [network review](svmf-static-network-review.md) owns the desired state and
handoff to DNS and Munin.

## Prepare and review

Run `deploy.py seal` with explicit `--baseline`, `--profile-baseline`, `--dashboard-baseline`,
`--operation-id` and new `--output` paths. The baseline is the accepted network
readiness capture; the profile baseline is the accepted persistent-profile save.
The dashboard baseline is the committed, independently verified Apache ACL
deployment, not its earlier read-only diagnostic or the failed HTTP network run.
The preparer checks both archived specifications, capture identities, execution
receipts and the readiness-to-profile-save hash chain. It never executes code
from an old evidence archive. Its output contains frozen repository code,
settings, an explicit specification, the pinned host key, public CA snapshot,
repository-owned HTTPS helper and `deployment.tar`.
`sealing.json` records the archive SHA-256 and expiry. All execution inputs are
inside the archive. Execution does not resolve a floating baseline.

The October 21 successor also binds the accepted NTP DNS archive/outcome and
unchanged runtime qualification in its specification. It uses the retained
October 20 host/profile/HTTPS pins, with strict execution-time rejection of drift;
preparation does not refresh live state. The archive binds the exact private
review through `review_sha256`. Its current approval checkpoint is recorded in
the [network review](svmf-static-network-review.md#current-checkpoint--october-21-2026).
No new fixture stage is required for these unchanged runtime sources.

Review the generated specification and exact execution command. In particular:

- Host/boot/MAC, profile UUID and filename, NetworkManager version/identity,
  full original file digest/metadata and address-generation identity metadata
  are pinned. Any drift fails before the profile write.
- Fixed IPv4 and ULA coexist with the existing generated ULA, global IPv6
  addresses and RA default route. The actual route to the NTP node must select
  the new ULA. No unrelated profile property may change, apart from the
  NetworkManager connection timestamp.
- The exact DNS VIPs and search domain must appear in the effective profile
  and system resolver configuration. The reviewed NTP name is
  `ntp1.local.theama.co`, with exact native results `10.1.0.51` and
  `fd36:5aa8:6971:1::51` before and after activation. Reject empty, wrong-family,
  mapped IPv4, extra or unexpected addresses even if getent exits 0. Failure
  evidence identifies the lookup family, exit status/output byte counts or
  timeout without exporting raw stderr. The archive rejects the nonexistent
  ntp2 dependency before contact. Accept the separate
  [NTP DNS prerequisite](../../homelab-dns/Unbound/docs/ntp1-ipv6-prerequisite-review.md)
  before a new production network operation.
  A stub-only resolver file requires a separately reviewed validation method;
  it is not silently accepted as direct VIP configuration.
- Dashboard gates are verified HTTPS on port 443: root `/`,
  `/static/style-new.css` and the accepted daily graph
  `/munin-cgi/munin-cgi-graph/J1-SVMF/J1-SVMF/apache_accesses-day.png`.
  Preserve `munin.local.theama.co` for SNI, certificate hostname and Host while
  connecting directly through the required literal family. Require nonempty
  200 HTML/CSS/PNG responses, PNG signature and the accepted certificate leaf.
  The pinned CA snapshot and helper are archive members. No DNS-only proof,
  redirect following, login, HTTP downgrade or verification bypass. The root,
  stylesheet and sample graph passed both original families after Apache ACL
  acceptance; that does not establish graph freshness or future static addressing.
- Apache, cron, SSH, Munin node and NetworkManager must remain active with
  identical PIDs, invocation IDs and restart counts. Apprise's existing
  loopback `/status` must return HTTP 200; Mailrise must answer a greeting and
  QUIT exchange. No SMTP message is sent. These probes do not infer container
  ownership or establish final notification delivery.

A bundle expires after 24 hours. An expired unexecuted bundle needs a fresh seal
and hash-bound approval. Do not edit an executed archive or its receipts.

## Authorized execution

Invoke the frozen `deploy.py` inside the approved output directory with
`execute --directory OUTPUT --sha256 APPROVED_SHA256`. The repository copy is
not a substitute for those reviewed bytes. The controller verifies the archive,
its closed regular-file member set, manifest, own source and pinned key.
It also verifies the frozen HTTPS helper and trust bytes before contact.

The controller consumes a local exclusive receipt before its first network
request. It checks the existing dashboard through both original address families,
then uses strict pinned-key SSH to stage an exclusive root-private operation at
`/var/lib/svmf-network/OPERATION_ID`. Reusing that operation ID fails. The remote
working directory is `/`; no interactive shell configuration is loaded.
A transient root systemd service runs the worker independently of the SSH session,
with no restart policy and a 480-second runtime limit. No package, persistent
service, firewall, controller, DNS or container configuration is changed.

The worker validates live identity and original state, creates an exact root-owned
0600 profile backup and fsyncs its data and directory. Durable state precedes the
native checkpoint and profile mutation. It creates a single-device 300-second
NetworkManager checkpoint without deleting existing checkpoints, changes only
reviewed settings on the existing UUID, and reactivates that profile.

Before commit, the controller opens fresh SSH sessions through each fixed literal
address. Connection sharing, proxying, forwarding, host-key updates and global
known-host files are disabled. Each session captures current network, resolver
and application evidence; the controller also checks the dashboard through that
address. Both observations must pass, refer to the same operation challenge and
be no more than 25 seconds old when accepted. Confirmation delivery is attempted
once. An ambiguous response is not permission to submit it again.

Each dashboard proof contains exactly the three verified responses for that
family and destination, with accepted leaf/type/PNG evidence. Response bodies
stay in memory; retain only hashes, bounded metadata and public certificate
identity. The existing bounded controller loop may repeat failed convergence
checks before the native checkpoint deadline; it never invents another path or
weakens TLS. The unchanged 25-second freshness check rejects slow/stale proof.
Each request retains the qualified helper's five-second socket timeout,
twelve-second wall deadline and 1048577-byte sample bound. Existing loopback
Apprise HTTP and Mailrise greeting/QUIT checks retain their earlier contract.

The worker rechecks every local acceptance gate and the owned checkpoint, with
at least 35 seconds left before native timeout. Only then may it destroy its own
checkpoint. The controller independently verifies terminal state and dashboard
access over both families. Only `committed` returns successful execution status;
rollback, held recovery and preflight failure return a nonzero execution status.
Private transport records retain arguments, payload hashes, stdout, stderr and
return codes. The exact profile backup remains on the target.

## Failure and inspection

If the controller disappears, the supervisor continues without treating the lost
connection as confirmation. The worker requests rollback when confirmation is
missing, provided manager/profile identity remains attributable to this operation.
A killed worker leaves the native timer armed. No checkpoint is assumed to
survive a NetworkManager restart, daemon crash or reboot.

Caught rollback must restore the full effective original profile, addressing,
NTP route sources, RA/global IPv6, resolver results and service health within a
60-second convergence window. The controller must independently re-establish SSH
and dashboard access through both original addresses. A successful rollback API
call alone is insufficient. Foreign profile or service drift holds recovery and
leaves the native guard to expire; the wrapper does not overwrite drift with a
manual backup restoration.

After interruption, run the frozen controller's `inspect --directory OUTPUT
--sha256 APPROVED_SHA256` for the same consumed operation. This bounded read-only
continuation checks IPv4, the original ULA and the intended ULA. It returns saved
state plus fresh full network checks, checkpoint registry and current file
metadata/digest where reachable. Inspection can read an expired executed bundle;
it cannot apply, confirm, restart a worker, clear checkpoints or restore a file.
Unreachable or drifted observations remain explicit failures. An interrupted
worker's saved phase can remain nonterminal even after native timeout restores
networking; inspection does not rewrite that history or infer accepted completion.

Do not run `execute` again, restart the transient worker or delete the operation
directory. Preserve root state, logs, exact backup, local receipts and transport
records. A failed write of a commit receipt also requires inspection: it does not
authorize rollback of a checkpoint already destroyed by successful commit.

## Console recovery hold

Local-console availability is operator-confirmed; console restoration has not
been exercised on svmf. If independent access or native recovery cannot be proven:

1. Use the console to inspect host/boot, NetworkManager service identity, current
   active UUID, checkpoint registry and the operation's durable state. Determine
   whether the native guard is still armed or has expired. Do not blindly restart
   NetworkManager, reboot, clear checkpoints or activate a profile.
2. Verify the root-private `original.nmconnection` digest and uid/gid/mode against
   the recorded backup and sealed original metadata. Compare the current saved
   file and effective settings; identify foreign drift before selecting recovery.
   The backup preserves exact bytes. Native recovery acceptance compares full
   effective settings, allowing only the connection timestamp to vary; it does
   not claim byte-identical file serialization after native rollback.
3. Prepare a separate recovery review for any exact-file restoration, reload or
   reactivation required outside the native path. Bind its identity, observed
   current state, commands, metadata, backup and independent acceptance checks
   to a new hash. The installation approval does not authorize an improvised
   console restoration, NetworkManager restart or reboot.
4. Keep DNS publication and Munin installation held until host-network acceptance
   is recorded. Schedule an approved later renewal/reboot observation to compare
   the accepted configuration and sources. Do not reboot during this stage.

## Local qualification

`test_deploy.py` covers gate failures, exact backup, exclusive receipts, stale or
incomplete dual-stack evidence, foreign drift, supervised staging, replay refusal
and recovery holds without target contact. CI and pre-commit run these offline
contracts. `test_native_deploy.py` runs the actual sealed controller and worker,
real SSH, native NetworkManager and root systemd supervisor in an isolated Podman
systemd container with a private DHCP/RA/DNS router and synthetic applications.
It refuses a host with pre-existing network interfaces. Build with
`munin-master-profile/Containerfile.deploy` from the recorded native fixture image.
Pin all executable/settings/image bytes and retain private per-case logs.

Native cases cover commit, controller loss, worker loss, failed application
health, foreign profile drift and interruption after the actual candidate keyfile
write. The seventh case serves only the intended NTP A record, reproduces
successful ahostsv6 mapped fallback and requires preflight rejection before
checkpoint, backup or profile write. After restoring only synthetic DNS, it
checks original access independently. Recovery readbacks originate in the independent router namespace through
fresh pinned-key SSH over both original families. The applications are synthetic;
these tests qualify wrapper behavior on Debian 12 amd64/NetworkManager 1.42.4.
They do not prove live ARM64 application continuity, production DAD, real resolver
behavior, console recovery or reboot persistence. Those remain explicit live gates.

The HTTPS successor fixture uses a private synthetic certificate, serves root,
stylesheet and daily PNG over TLS, and returns an HTTP redirect on port 80.
This prevents the old plaintext gate from passing accidentally. Use
[run_native_https.py](munin-master-profile/run_native_https.py) with an immutable
image ID, new private evidence root and revision; it records full Podman/test
arguments, source hashes, original logs, terminal status and retained stopped
container identity for each scenario. At most two independent fixtures run
concurrently. No fixture image or application is production acceptance.
