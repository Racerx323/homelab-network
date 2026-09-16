# UniFi controller access

This is the shared UniFi connection procedure owned by `homelab-network`.
Consumers in sibling repositories, including `homelab-server-configs`, reference
this procedure for controller evidence and network-owner coordination.

## Connection and credentials

- Use `https://udmbt.local.theama.co` for the local controller. Its IPv4 address
  is `10.1.0.1`. Use the FQDN for TLS hostname verification; do not substitute an
  IP URL, disable certificate verification, or override the TLS name.
- The read-only local audit credential reference is Doppler project
  `homelab-dev`, config `prd_unifi`, secret `AUDIT_LOCAL`. Retrieve it only for
  authorized queries, keep its value in process memory, and never print it,
  persist it in evidence, or include it in Git or deployment hashes.
- Cloud Site Manager is a separate endpoint, `https://api.ui.com`, with the
  separate `AUDIT_SITE_MANAGER` reference in the same Doppler configuration.
  Do not interchange local and cloud credentials or send either credential to
  another endpoint. A cloud credential reference does not prove permissions.
- Verify DNS and the certificate chain before authenticated access. Stop and
  investigate resolution, trust, authentication or authorization failures;
  never bypass TLS verification to continue.

## Query scope and evidence

Read-only collection requires the task's authorized target and scope. This
reference grants no permission to modify switch ports, PoE, leases, networks,
firewall rules or controller settings. Follow the network owner's deployment
process for changes.

For host power evidence, correlate the host MAC with the observed switch and
port. Record the timestamp, negotiated PoE class/type, link status, measured
power and explicit allocation if exposed. An absent allocation field stays
unknown; observed draw and switch-wide budget are not per-port allocation.
Preserve bounded, sanitized responses privately. Exclude credentials and private
identities from public reports.

Revalidate current access and API behavior when executing a future task; the
reference describes the intended connection, not a permanent proof of availability.
