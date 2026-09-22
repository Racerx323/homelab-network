# Backend guard preflight review

Read-only collection on September 22, 2026 at 19:11 UTC completed on the target
and Munin master. Classification: first-install baseline passed with explicit
monitoring/TLS limitations. Deployment is not authorized or ready.

- Target identity and UID999 match; intended IPv4 and permanent ULA are present.
- nftables 1.1.3, systemd 257.13-1~deb13u1 and Podman 5.4.2 were observed.
- nft ruleset and default/legacy IPv4/IPv6 iptables exports are empty. No existing
  DNAT, nft flowtable or custom routing policy is present. eth0 ingress/egress tc
  filters are empty; detailed link output shows no attached XDP program.
- All seven owned install files and the operation directory are absent. Guard
  and recovery units are not found. Distro nftables service is disabled/inactive;
  ufw/firewalld units are not found. Existing vendor user-manager drop-in retained.
- TCP8080 is closed; rootless container inventory is empty. PostgreSQL, Redis and
  migration units are inactive; web/worker/scheduler units are not installed.
- SSH collection succeeded. Fresh SSH and Webmin TCP connections succeeded over
  both families. Webmin certificate verification fails with a self-signed
  certificate, consistent with the deferred Caddy follow-up; trusted HTTPS is
  not claimed. No credentials were submitted and TLS checking was not bypassed.
- Munin master successfully listed plugins and fetched load over IPv4. IPv6 TCP
  connected but closed without a banner. Node configuration permits localhost
  and the master's IPv4 only; its selected ULA has no allow entry. This explains
  the existing protocol rejection; no firewall is installed. Preserve working
  IPv4 monitoring; adding IPv6 monitoring would be a separate owner change.
- The master has a usable on-link ULA route for the later negative TCP8080 test;
  refresh its selected source then. Munin's protocol ACL does not invalidate
  using that host as a firewall test vantage.

No configuration, services, packets rules, proxy routes or application state were
changed. No SMART queries or containers were started. Prior physical recovery
availability confirmation remains user-provided, not remotely verifiable.
Collection exit statuses: both initial SSH calls and the follow-up returned 0;
all captured target commands returned 0. No captured output was truncated.

Private evidence is retained under
`/home/aaron/code/.local-evidence/nautobot-backend-preflight-20260922/`;
[the evidence manifest](backend-preflight.json) records hashes and decisions. Next complete the guard-install launcher, rendered
bundle and recovery reporting/tests described in BACKEND_GUARD_PREPARATION.md,
then freeze a separate exact deployment bundle for approval. Effective packet
qualification and reboot persistence remain later stages.
