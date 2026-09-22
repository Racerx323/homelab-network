#!/usr/bin/env python3
"""Fixed target checks shared by installation, acceptance and recovery."""
import hashlib
import json
from pathlib import Path
import backend_guard as guard
from network_policy import normalized_table, digest

UNITS = ['nautobot-web', 'nautobot-worker', 'nautobot-scheduler',
         'nautobot-postgresql', 'nautobot-redis', 'nautobot-migration']


def identity():
    if guard.run(['hostname', '-s']).strip() != 'j2-svpi4mf' or guard.run(['id', '-u', 'nautobot']).strip() != '999':
        raise RuntimeError('target identity drift')
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def stopped():
    if guard.run(['/usr/bin/ss', '-H', '-ltn', 'sport', '=', ':8080']).strip():
        raise RuntimeError('backend listener present')
    prefix = ['runuser', '-u', 'nautobot', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/999',
              'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/999/bus']
    states = guard.run(prefix + ['systemctl', '--user', 'show', '-p', 'ActiveState', '--value'] +
                       [x + '.service' for x in UNITS]).split()
    if len(states) != len(UNITS) or any(x != 'inactive' for x in states):
        raise RuntimeError('application not stopped')
    if json.loads(guard.run(prefix + ['podman', 'ps', '-a', '--format', 'json'])):
        raise RuntimeError('unexpected rootless containers')


def unrelated():
    rules = json.loads(guard.run(['/usr/sbin/nft', '-j', 'list', 'ruleset']))
    rules['nftables'] = [x for x in rules['nftables'] if not any(
        isinstance(v, dict) and v.get('family') == 'inet' and
        (v.get('table') == 'nautobot_backend' or (k == 'table' and v.get('name') == 'nautobot_backend'))
        for k, v in x.items())]
    # Current reviewed baseline is empty. Never accept added unrelated rules silently.
    if normalized_table(rules) != {'nftables': []}:
        raise RuntimeError('unrelated nft rules changed')
    for command in ['iptables-save', 'ip6tables-save', 'iptables-legacy-save', 'ip6tables-legacy-save']:
        if guard.run([command]).strip():
            raise RuntimeError('iptables baseline changed')
    return digest(normalized_table(rules))


def files(expected):
    for name, sha in expected.items():
        p = Path(name)
        raw = guard.trusted(p)
        mode = 0o440 if name.startswith('/etc/sudoers.d/') else 0o644
        if p.stat().st_mode & 0o777 != mode or hashlib.sha256(raw.encode()).hexdigest() != sha:
            raise RuntimeError('installed artifact mismatch')


def installed(value):
    if identity() != value['boot_id']:
        raise RuntimeError('boot changed')
    stopped()
    if unrelated() != value['unrelated_digest']:
        raise RuntimeError('unrelated policy changed')
    files(value['files'])
    guard.verify(guard.table(), value['table_digest'])
    if guard.run(['systemctl', 'is-active', 'nautobot-backend-guard.service']).strip() != 'active':
        raise RuntimeError('guard inactive')
    if guard.run(['systemctl', 'is-enabled', 'nautobot-backend-guard.service']).strip() != 'enabled':
        raise RuntimeError('guard disabled')
    for prop in ['After', 'Requires']:
        if 'nautobot-backend-guard.service' not in guard.run(['systemctl', 'show', 'user@999.service', '-p', prop, '--value']).split():
            raise RuntimeError('user manager dependency missing')
    guard.run(['runuser', '-u', 'nautobot', '--', 'sudo', '-n', '/usr/bin/python3', '-I',
               '/usr/local/lib/nautobot-network/backend_guard.py', 'check'])
