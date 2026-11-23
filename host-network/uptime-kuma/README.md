# Kuma host networking

NetworkManager manages Ethernet on `j2-svpi3bmf`. The [address playbook](ansible/permanent-ula.yaml) uses a checkpoint when adding the permanent ULA. The [deployment manifest](../../../homelab-monitoring-observability/uptime-kuma/manifests/deployment.yaml) identifies the interface and expected IPv4 and IPv6 addresses.

## Router advertisement renewal

The network owner should verify timed IPv6 router advertisement renewal before the next host network or container-runtime migration, or earlier if global IPv6 connectivity or the default route disappears. The accepted installation showed the expected addresses and route after reboot and backend promotion. Those snapshots did not span renewal.

On the affected interface, record the advertised router lifetime and the IPv6 default route, global address and permanent ULA. Observe the next advertisement and the route lifetime refreshing before expiry with forwarding enabled. Confirm the route and addresses persist and IPv6 connectivity works afterward. If renewal fails, retain the timestamps and NetworkManager state for the network owner. This follow-up requires no deployment change now.
