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
    if kind not in {'review_only', 'standby_route_retry'}:
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
    manifest = {'kind': kind, 'execution_ready': kind == 'standby_route_retry', 'files': hashes,
                'blockers': [] if kind == 'standby_route_retry' else ['review_only_not_executable']}
    if kind == 'standby_route_retry':
        manifest['scope'] = ('single standby preferred-source route retry with protected predecessor archive; '
                             'primary read-only health probes; bounded standby interruption permitted; '
                             'excludes firewall, intentional failover and Caddy changes')
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    (destination / 'bundle.json').write_bytes(raw)
    identity = hashlib.sha256(raw).hexdigest()
    (destination / 'SHA256').write_text(identity + '\n')
    return identity


if __name__ == '__main__':
    print(freeze(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else 'review_only'))
