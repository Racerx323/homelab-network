# Primary-route read-only preflight

Preflight passed on September 22, 2026. No live mutations were performed.

- Primary j1-svpihole0: NetworkManager 1.42.4, active eth0 profile
  `178f6c60-c62a-3c6c-9fae-04ebf2c4fdc3`, root-owned mode 0600 keyfile.
  No conflicting destination route or owned helper/state residue was found.
  The Caddy-UID route query still selects the proxy VIP ::56 instead of ::53.
- Standby j1-svpihole00: accepted static /128 route selects ::54; saved accepted
  state, current profile hash, boot ID and deployed helper/policy hashes match
  the accepted bundle. Both permanent ULAs are non-tentative and permanent.
- Primary is MASTER and owns all four DNS/proxy VIPs; standby is BACKUP.
  All four services are active on both nodes. All 12 controller DNS/HTTPS checks
  pass over both families with normal TLS verification and exact DNS answers.
  These are point-in-time checks, not a new soak or failover qualification.
- Primary console/physical recovery is confirmed available by the user.
- Running Keepalived command lines contain no alternative config argument; the
  main config has no include directives and predates current daemon startup.
  Its coupled PIHOLE group matches observed roles and VIPs. Use its 0.5-second
  advertisement interval and 10-second preemption delay, with health interval 3,
  timeout 2, fall 2 and rise 3. The separate conf.d/caddy-ha.conf is unreferenced;
  its 30-second setting is not the active coupled-group timing. Do not edit it.

Next: implement and locally test the proposed primary handoff, route transaction,
failback and watchdog recovery in the existing owner path, then freeze a new
execution bundle. Planned handoff is additional live scope; no execution is
approved by this preflight. Require ownership and service readback, rather than
assuming the configured delay proves a handover completed. Preserve standby's
accepted route. No target firewall, application startup, reboot or package change.

Private evidence: `/home/aaron/code/.local-evidence/nautobot-primary-route-preflight-20260922`.
