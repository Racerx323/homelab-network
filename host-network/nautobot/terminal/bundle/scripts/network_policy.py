#!/usr/bin/env python3
"""Offline policy compiler; no host contact. Privileged guard uses fixed artifacts."""
import hashlib
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_policy(path=ROOT / 'policy.json'):
    value = json.loads(path.read_text())
    expected = {'schema_version', 'execution_authorized', 'destination4', 'destination6',
                'port', 'interface', 'proxies', 'target', 'first_route_target', 'rollback_seconds'}
    if set(value) != expected or value['schema_version'] != 1 or value['execution_authorized'] is not False:
        raise ValueError('inactive policy required')
    if value['port'] != 8080 or value['interface'] != 'eth0' or value['target'] != 'j2-svpi4mf':
        raise ValueError('unexpected target contract')
    if value['first_route_target'] != 'pihole00' or value['rollback_seconds'] != 300:
        raise ValueError('unexpected ordering/deadline')
    if value['destination4'] != '10.1.2.170' or value['destination6'] != 'fd36:5aa8:6971:1::170':
        raise ValueError('destination drift')
    if value['proxies'] != {
        'pihole0': {'ipv4': '10.1.0.53', 'ipv6': 'fd36:5aa8:6971:1::53'},
        'pihole00': {'ipv4': '10.1.0.54', 'ipv6': 'fd36:5aa8:6971:1::54'},
    }:
        raise ValueError('permanent allowlist drift')
    for host in value['proxies'].values():
        assert ipaddress.ip_address(host['ipv4']).version == 4
        assert ipaddress.ip_address(host['ipv6']).version == 6
    return value


def nft_rules(p):
    sources4 = ', '.join(x['ipv4'] for x in p['proxies'].values())
    sources6 = ', '.join(x['ipv6'] for x in p['proxies'].values())
    return f'''table inet nautobot_backend {{
    comment "homelab-network:nautobot-backend:v1"
    chain ingress {{
        type filter hook prerouting priority -110; policy accept;
        iifname "lo" accept
        ip daddr {p['destination4']} tcp dport 8080 ip saddr {{ {sources4} }} counter accept comment "allow-v4"
        ip daddr {p['destination4']} tcp dport 8080 counter drop comment "deny-v4"
        ip6 daddr {p['destination6']} tcp dport 8080 ip6 saddr {{ {sources6} }} counter accept comment "allow-v6"
        ip6 daddr {p['destination6']} tcp dport 8080 counter drop comment "deny-v6"
    }}
}}
'''


def route_value(p, host):
    if host not in p['proxies']:
        raise ValueError('unknown proxy')
    return f"{p['destination6']}/128 src={p['proxies'][host]['ipv6']}"


def route_commands(p, host, uuid):
    import uuid as uuid_module
    if str(uuid_module.UUID(uuid)) != uuid:
        raise ValueError('canonical profile UUID required')
    value = route_value(p, host)
    return {
        'apply': ['nmcli', 'connection', 'modify', 'uuid', uuid, '+ipv6.routes', value],
        'reapply': ['nmcli', 'device', 'reapply', p['interface']],
        'remove': ['nmcli', 'connection', 'modify', 'uuid', uuid, '-ipv6.routes', value],
    }


def normalized_table(value):
    """Ignore volatile handles/counters, retain every semantic rule and its order."""
    if isinstance(value, list):
        return [normalized_table(x) for x in value if not (isinstance(x, dict) and 'metainfo' in x)]
    if isinstance(value, dict):
        return {k: normalized_table(v) for k, v in value.items()
                if k not in {'handle', 'packets', 'bytes'}}
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def acceptance(observed):
    """All required results must carry true measured outcomes, never missing defaults."""
    keys = ['proxy0_v4', 'proxy0_v6', 'proxy00_v4', 'proxy00_v6', 'deny_v4', 'deny_v6',
            'deny_v4_counter_increased', 'deny_v6_counter_increased', 'listener_control_before',
            'listener_control_after', 'ssh_new', 'ssh_retained', 'webmin', 'munin', 'recovery',
            'unrelated_rules_unchanged', 'listener_removed', 'sources_permanent', 'both_ha_states']
    return all(observed.get(k) is True for k in keys)
