# Live backend packet qualification preparation

## Result

The approved live trial passed; [packet-result.json](packet-result.json) records
its bounded scope and remaining limitations. Listener/tunnel cleanup and unchanged
guard were independently verified. Git archival remains pending; do not rerun the
consumed bundle.

## Historical preparation gate and purpose

Guard installation is accepted. Its terminal archive must be published and
verified before activating this operation. This document defines the next stage;
the path is implemented and locally tested in the [operation](PACKET_QUALIFICATION_OPERATION.md).
A frozen exact bundle requires separate execution authorization. Keep the application, database and workers stopped.

Prove actual TCP8080 allow/deny behavior on the installed target guard using a
short-lived disposable listener. A closed port, route lookup, or a successful
local namespace test cannot substitute for this live evidence.

## Targets and scope

- Listener and counter collection: `ama@10.1.2.170`, j2-svpi4mf.
- Allowed clients: `pi@10.1.0.53` and `pi@10.1.0.54` over IPv4 and ULA.
- Denied client: `pi@10.1.3.83` over IPv4 and its freshly observed selected ULA.
- Controller: protected evidence, bounded orchestration and SSH-tunnel recovery.

The installed guard, proxy routes, DNS, Caddy and HA configuration stay unchanged.
No HA transition or reboot is included. Prior route-operation evidence covers
source selection under both HA ownership states; this packet stage exercises
current ownership only. Actual Caddy request-source behavior remains a later
Caddy-owned check. Do not claim all final network acceptance from this one stage.

## Listener design

Use one neutral Python listener under a transient, independently timed service
running as the Nautobot account. Bind only 10.1.2.170:8080,
[fd36:5aa8:6971:1::170]:8080 and 127.0.0.1:8080. No wildcard, global IPv6, extra port,
container image or application process is allowed. Return a fixed test-only
response with a per-operation non-secret nonce, and record bounded peer/local
address metadata. Accept no credentials, uploads or executable input.

The node lifetime is at most 180 seconds; the controller trial is at most 120
seconds. Terminate all listener children at expiry. Refuse an existing unit,
listener, residue or active application before staging. The watchdog must be
independent of controller connectivity and armed before exposing the listener.
Failure cleanup stops only the exact owned listener; it never removes the guard.
No installation or privilege grant is needed for port8080.

## Preflight and ordered checks

1. Verify accepted installed-file/table identities, enabled guard, startup
   dependency, target boot and stopped application. Check no TCP8080 listener.
   Capture counter baselines, proxy Caddy-UID routes and the Munin master's ULA.
   Verify normal management and IPv4 Munin polling. Refuse drift before mutation.
2. Start the bounded listener and verify exact address ownership and service
   identity. Record its socket metadata and the independent expiry deadline.
3. From each proxy, use unbound fresh TCP connections to each target family.
   Require the correct nonce response and listener-observed permanent peer source.
   Use three attempts maximum with three-second connection/response timeouts.
   Do not force-bind the source and call that proof of normal source selection.
4. Bracket each denied-source probe with a successful allowed probe to that same
   target family. Require the denied client to time out without receiving the
   nonce and the matching installed deny-rule counter to increase. Capture
   before/after counters and timestamps; unrelated traffic can also increment
   counters, so counter growth alone is insufficient. Where correlation is
   ambiguous, report incomplete rather than infer proof.
5. Verify the loopback endpoint through a bounded SSH forwarding session to the
   target, with a dynamically selected local port and explicit teardown. Do not
   expose the tunnel on a wildcard controller address.
6. Recheck new SSH connections, Webmin TCP reachability and successful IPv4
   Munin load retrieval. Preserve a retained SSH session for continuity evidence.
7. Stop the listener and prove unit/process/socket cleanup, including all three
   binds and the forwarding session. Verify guard identity unchanged, unrelated
   rules unchanged, no application startup, and management/monitoring health.

IPv6 Munin protocol polling remains an explicit future monitoring-owner action:
its current node ACL allows the master over IPv4 only. The master still supplies
an IPv6 negative-test vantage. Webmin certificate trust and lack of external IPv6
vantage remain documented limitations; do not bypass TLS or broaden ACLs here.

## Recovery and acceptance

On any failed or uncertain check, stop additional probes, stop the owned listener
and tunnel, and retain the restrictive guard. On controller loss, the node expiry
stops the listener. Read back actual closure and final health before declaring
cleanup; an inactive controller alone is not evidence. If closure is unverified,
report manual intervention and do not remove or relax the guard.

Accept only with the complete family/client matrix, expected response/source
metadata, paired deny evidence, healthy bracketing probes, unchanged guard and
verified cleanup. Save per-check outcomes and hashes in a sanitized result; raw
addresses and logs remain private. Archive the terminal definition and result
before handing qualification evidence to Nautobot startup.

## Implementation milestone

Implement the bounded listener/service, Ansible orchestration, client probes,
counter collector, expiry and cleanup readback as one separately frozen bundle.
Tests must exercise IPv6-only binding, wrong nonce/source, missing or unrelated
counter growth, closed-listener false negatives, partial bind/start failure,
controller loss, expiry, cleanup failure and unchanged guard. Run local namespace
integration tests and disabled-execution gates before requesting exact-bundle
approval. Do not fold application startup or reboot qualification into this stage.
