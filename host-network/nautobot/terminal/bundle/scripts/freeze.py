#!/usr/bin/env python3
"""Freeze a review bundle. Never an execution authorization or live launcher."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_policy import ROOT, load_policy, nft_rules


def freeze(destination, kind="review_only"):
    if kind not in {'review_only', 'standby_route_retry', 'primary_route', 'guard_install'}:
        raise ValueError('Consumed first-install kind is blocked; use reviewed retry')
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    hashes = {}
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            if path.is_symlink():
                raise ValueError('symlink in bundle')
            relative = path.relative_to(ROOT)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            hashes[str(relative)] = hashlib.sha256(target.read_bytes()).hexdigest()
    (destination / 'rendered').mkdir(exist_ok=True)
    rules = nft_rules(load_policy())
    (destination / 'rendered/rules.nft').write_text(rules)
    hashes['rendered/rules.nft'] = hashlib.sha256(rules.encode()).hexdigest()
    manifest = {'kind': kind, 'execution_ready': kind in {'standby_route_retry', 'primary_route', 'guard_install'}, 'files': hashes,
                'blockers': [] if kind in {'standby_route_retry', 'primary_route', 'guard_install'} else ['review_only_not_executable']}
    if kind in {'standby_route_retry', 'primary_route', 'guard_install'}:
        manifest['scope'] = ('single standby preferred-source route retry with protected predecessor archive; '
                             'primary read-only health probes; bounded standby interruption permitted; '
                             'excludes firewall, intentional failover and Caddy changes')
    if kind == 'primary_route':
        manifest['scope'] = 'Primary-only route mutation with Keepalived stop/start, planned cluster handoff/failback, read-only standby probes and 600-second independent recovery; excludes firewall, Caddy configuration and application startup'
    if kind == 'guard_install':
        # Parse in an isolated local network namespace, never on a production host.
        rendered = subprocess.run(['unshare', '--user', '--map-root-user', '--net',
                                   sys.executable, str(destination / 'scripts/render_guard.py')],
                                  capture_output=True, text=True, check=True, timeout=30)
        table_digest = rendered.stdout.strip()
        if len(table_digest) != 64 or any(c not in '0123456789abcdef' for c in table_digest):
            raise ValueError('invalid parser digest')
        (destination / 'rendered/expected-table.sha256').write_text(table_digest + '\n')
        inputs = {
            '/usr/local/lib/nautobot-network/backend_guard.py': 'scripts/backend_guard.py',
            '/usr/local/lib/nautobot-network/network_policy.py': 'scripts/network_policy.py',
            '/etc/nautobot-backend/rules.nft': 'rendered/rules.nft',
            '/etc/nautobot-backend/expected-table.sha256': 'rendered/expected-table.sha256',
            '/etc/systemd/system/nautobot-backend-guard.service': 'templates/nautobot-backend-guard.service',
            '/etc/systemd/system/user@999.service.d/50-nautobot-network.conf': 'templates/user-manager.conf',
            '/etc/sudoers.d/nautobot-network': 'templates/nautobot-network.sudoers',
        }
        installation = {'baseline': 'all_owned_files_absent', 'table_digest': table_digest,
                        'files': {dest: hashlib.sha256((destination / src).read_bytes()).hexdigest()
                                  for dest, src in inputs.items()}}
        (destination / 'rendered/installation.json').write_text(json.dumps(installation, sort_keys=True, indent=2) + '\n')
        for name in ['rendered/expected-table.sha256', 'rendered/installation.json']:
            hashes[name] = hashlib.sha256((destination / name).read_bytes()).hexdigest()
        manifest['scope'] = 'Install stopped Nautobot host backend guard and persistence only; 300-second recovery; no listener, application startup, proxy changes or reboot'
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    (destination / 'bundle.json').write_bytes(raw)
    identity = hashlib.sha256(raw).hexdigest()
    (destination / 'SHA256').write_text(identity + '\n')
    return identity


if __name__ == '__main__':
    print(freeze(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else 'review_only'))
