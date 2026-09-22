# Primary route operation specification

## Execution scope

Only an exact approved `primary_route` bundle may execute `ansible/primary-route.yaml`
through `scripts/run_bundle.py`. Mutation target: pi@10.1.0.53 (j1-svpihole0).
Standby pi@10.1.0.54 is read-only throughout. Recovery availability for the primary
was explicitly confirmed during preflight. Reconfirm if that availability changes.

The operation installs root-owned network helpers and inactive policy, preserves
the primary profile and journal cursor, and arms an independent 600-second timer
before stopping primary Keepalived. DNS/Caddy processes stay running. All four
DNS/proxy VIPs must be observed on the standby and serving successfully before
the primary route can be written. The shared transaction adds only the on-link
IPv6 /128 for `fd36:5aa8:6971:1::170` with preferred source `::53` on eth0.

After 60 seconds of stable checks under standby ownership, start primary
Keepalived, observe delayed failback, require original ownership and 60 seconds
of stable final health, then accept and disarm the watchdog under the node lock.
The primary source must remain ::53 when it regains the VIPs; standby remains ::54.
The observed 10-second preemption setting is not proof that failback completed.

## Numerical bounds and acceptance

- Controller probes start every five seconds, each with a four-second outer limit.
  A sampling gap over eight seconds blocks acceptance. HTTPS retains TLS validation;
  all DNS answers and HTTP 204 checks use the same accepted standby endpoints.
- Handoff and failback each allow at most 60 seconds for complete ownership and
  service convergence. During the first ten seconds of these planned transitions,
  failed cluster endpoint probes are retained but do not alone reject the operation.
  After that window any cluster endpoint failure rejects it. This is an explicit
  bounded cluster-transition allowance, not a zero-loss claim.
- Primary route settlement remains limited to 20 seconds and requires three
  consecutive route/source/address/DAD matches. Primary-only temporary health/SSH
  failure may recover within 60 seconds from the controller apply marker.
- Require 60 seconds of stable checks after applying the route and another
  60 seconds after restoring primary ownership. Missing evidence, boot changes,
  configuration drift, standby source/profile drift and incorrect final route
  selection prevent acceptance. Primary Keepalived is expected inactive only
  during the handoff/apply/settled phases; original service state is required finally.
- The controller process is bounded to 900 seconds. The node watchdog expires
  after 600 seconds even if the controller disappears. Generic node commands have
  25-second bounds. The timer is transient and does not survive reboot; reboot is
  unauthorized and an unexpected boot change requires console recovery review.

## Failure and recovery

Ansible attempts immediate recovery after task failure. If SSH becomes unreachable,
rescue may not execute; leave the node watchdog armed and inspect its eventual
result. Never equate an inactive timer with proven recovery.

Before a route write, recovery restores primary Keepalived only. After a route
write, it uses the existing exact-profile rollback and always attempts to start
primary Keepalived, even if route rollback fails. A rollback error remains explicit
manual intervention, never acceptance. The standby accepted route is untouched.
Controller recovery verification separately checks the original roles and stable
service without clearing the original failure history.

Unknown existing primary artifacts or state cause refusal. Staging failure leaves
only inert helpers and evidence; no speculative deletion or rerun is performed.
Protected evidence directories are `/var/lib/nautobot-primary-route` and
`/var/lib/nautobot-proxy-route`. The former owns maintenance/recovery state and the
latter owns the route transaction. Raw profile backups remain root-private.

Exact manual recovery command, only within the authorized recovery scope:

```bash
sudo /usr/bin/python3 -I /usr/local/lib/nautobot-network/primary_route.py rollback
```

If SSH is unavailable, use the confirmed primary console recovery path. Preserve
state and restore the captured profile through its manager before restoring
Keepalived. Do not alter the second node to hide failed primary recovery.

## Bundle command and exclusions

```bash
python3 /PATH/TO/FROZEN/scripts/run_bundle.py \
  --bundle /PATH/TO/FROZEN --approved-sha256 APPROVED_SHA256
```

The bundle binds this specification, primary and shared helpers, phase collector,
Ansible path, tests and policy. Preflight hashes pin primary profile/HA configuration
and standby HA/profile identities. No firewall installation, Caddy configuration
change, Nautobot startup, package change, reboot or standby mutation is included.
Actual Caddy-to-Nautobot application traffic, persistence through reboot and later
backend enforcement remain separate acceptance stages.
