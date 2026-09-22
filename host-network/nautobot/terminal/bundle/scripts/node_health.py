#!/usr/bin/env python3
"""Read-only node evidence, streamed on stdin over strict SSH; never installed."""
import json
from pathlib import Path
import subprocess


def read(args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=2).stdout


def collect():
    return {
        'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'hostname': read(['hostname', '-s']).strip(),
        'addresses': [a['local'] for r in json.loads(read(['ip', '-j', 'address', 'show', 'dev', 'eth0'])) for a in r.get('addr_info', [])],
        'services': read(['systemctl', 'is-active', 'caddy', 'keepalived', 'pihole-FTL', 'unbound']).split(),
        # Last group transition describes the coupled DNS/proxy ownership state.
        'transition': json.loads(read(['journalctl', '-b', '-u', 'keepalived', '--no-pager',
                                     '-g', 'VRRP_Group\\(PIHOLE_DUALSTACK\\) Syncing instances to',
                                     '-n', '1', '-o', 'json'])),
    }


if __name__ == '__main__':
    print(json.dumps(collect()))
