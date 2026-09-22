# Packet qualification operation

## Activation and scope

The `packet_qualification` bundle is executed only by its frozen `run_bundle.py`
with the exact approved SHA-256. The freezer pins the accepted guard archive tag
and commit and embeds its seven-file installation identity. The launcher verifies
all inputs twice before Ansible. The false-default playbook gate refuses contact
without launcher activation. Do not invoke the playbook directly.

Targets: listener on ama@10.1.2.170; read-only probes on pi@10.1.0.53,
pi@10.1.0.54 and pi@10.1.3.83. No proxy mutation or HA transition. No guard removal,
application startup, package installation, Caddy publication or reboot. The
[preparation](PACKET_QUALIFICATION_PREPARATION.md) defines the acceptance matrix.

## Implementation and limits

Ansible stages fixed root-owned scripts and the accepted guard identity under
`/var/lib/nautobot-packet-trial`, refusing existing residue. It verifies the stopped
accepted guard and records the boot before starting a transient service as
Nautobot. The directory is traversable for the unprivileged listener; state and
identity inputs are root-only. Root helper commands always run from `/`.

The listener binds only the exact IPv4, ULA and loopback TCP8080 addresses.
IPv6 sockets are IPv6-only. It reads no client input and returns bounded JSON with
a non-secret nonce and observed peer/local addresses. A partial bind failure
closes all sockets. It accepts at most 64 connections and self-expires after 170
seconds. Systemd independently enforces 175 seconds plus a five-second stop bound,
with control-group cleanup. Readiness requires the exact three sockets owned by
the service PID, correct User and runtime bound.

The controller trial uses a 120-second process-group timeout with five-second
forced termination. The outer Ansible bound is 240 seconds including staging and
cleanup. SSH probes use 12-second subprocess limits; individual TCP probes use
three-second connection/read limits. The trial does not retry failed policy probes.
A retained, loopback-only SSH tunnel is checked before and after the client matrix,
then terminated and its local port checked closed. GNU timeout terminates the
probe process group, including its tunnel, if normal cleanup cannot run.

Unbound probes verify nonce, peer and destination against expected permanent
sources. Fresh Caddy-UID IPv6 routes must also match. Denial requires timeout,
matching source, no response, the relevant deny-counter increase and no other-family
deny increase, bracketed by healthy allowed probes. Snapshots retain timestamps.
Counter attribution remains limited if unrelated matching traffic overlaps; review
ambiguous evidence rather than claim unique attribution from counters alone.

## Cleanup and result

Ansible always attempts listener stop after the start block, even when readiness
or probes fail. The helper checks no TCP8080 socket, MainPID zero, unchanged boot,
accepted guard baseline and unchanged full rules identity before recording cleaned.
It never removes the guard. Retained root-owned trial artifacts/evidence are
intentional residue; they block an automatic rerun. The current application remains
stopped throughout.

Independent controller readback requires cleaned state, no listener, unchanged
rules, passed probes and final SSH/Webmin-TCP/IPv4-Munin health. A failed playbook
never becomes accepted from a successful cleanup label. On timeout or lost SSH,
wait for node expiry and collect actual closure/health evidence; do not infer
cleanup from elapsed time. Retain the guard if anything is uncertain.

The fixed node cleanup command, within an approved recovery scope, is:

```text
cd / && sudo -n /usr/bin/python3 -I /var/lib/nautobot-packet-trial/packet_node.py cleanup
```

After acceptance archive exact inputs and sanitized outcomes. Actual Caddy
requests, other HA ownership, reboot persistence, external IPv6 and application
readiness remain separately scoped. Existing Webmin certificate trust and IPv6
Munin polling limitations remain unchanged.
