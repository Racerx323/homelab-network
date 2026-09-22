#!/usr/bin/env python3
"""Read-only node evidence, streamed on stdin over strict SSH; never installed."""
import json
import hashlib
import sys
from pathlib import Path
import subprocess


def read(args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=2).stdout


def collect():
    value = {
        'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'hostname': read(['hostname', '-s']).strip(),
        'addresses': [a['local'] for r in json.loads(read(['ip', '-j', 'address', 'show', 'dev', 'eth0'])) for a in r.get('addr_info', [])],
        'services': subprocess.run(['systemctl','is-active','caddy','keepalived','pihole-FTL','unbound'], text=True,capture_output=True,timeout=2).stdout.split(),
        # Last group transition describes the coupled DNS/proxy ownership state.
        'transition': json.loads(read(['journalctl', '-b', '-u', 'keepalived', '--no-pager',
                                     '-g', 'VRRP_Group\\(PIHOLE_DUALSTACK\\) Syncing instances to',
                                     '-n', '1', '-o', 'json'])),
    }

    if '--primary-route' in sys.argv:
        value['ha_sha256']=hashlib.sha256(Path('/etc/keepalived/keepalived.conf').read_bytes()).hexdigest()
        value['profile_sha256']=hashlib.sha256(Path('/etc/NetworkManager/system-connections/Wired connection 1.nmconnection').read_bytes()).hexdigest()
        uid=read(['id','-u','caddy']).strip()
        value['source']=json.loads(read(['ip','-6','-j','route','get','fd36:5aa8:6971:1::170','uid',uid]))[0].get('prefsrc')
    return value


if __name__ == '__main__':
    print(json.dumps(collect()))
