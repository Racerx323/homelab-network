#!/usr/bin/env python3
"""Fixed-path root guard. Check is read-only and suitable for a narrow sudo rule."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_policy import normalized_table, digest

BASE = Path('/etc/nautobot-backend')
NFT = '/usr/sbin/nft'


def run(args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=20,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError('command failed: ' + args[0])
    return result.stdout


def trusted(path):
    for item in [path, *path.parents]:
        st = item.lstat()
        if item.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('untrusted artifact')
    return path.read_text()


def table():
    all_tables = json.loads(run([NFT, '-j', 'list', 'tables']))['nftables']
    present = any(x.get('table', {}).get('family') == 'inet' and
                  x.get('table', {}).get('name') == 'nautobot_backend' for x in all_tables)
    return json.loads(run([NFT, '-j', 'list', 'table', 'inet', 'nautobot_backend'])) if present else None


def verify(current, expected):
    if current is None or digest(normalized_table(current)) != expected:
        raise RuntimeError('backend guard missing or drifted')


def apply(rules, expected):
    current = table()
    if current is not None:
        verify(current, expected)  # refuse takeover or silent repair of drift
        return
    run([NFT, '--check', '-f', '-'], rules)
    run([NFT, '-f', '-'], rules)
    verify(table(), expected)


def remove(expected):
    # Never open a running backend during rollback, regardless of ownership.
    listeners = run(['/usr/bin/ss', '-H', '-ltn', 'sport', '=', ':8080'])
    if listeners.strip():
        raise RuntimeError('retain guard: backend listener present')
    current = table()
    if current is None:
        return
    verify(current, expected)
    run([NFT, '-f', '-'], 'delete table inet nautobot_backend\n')
    if table() is not None:
        raise RuntimeError('guard removal unverified')


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in {'check', 'apply', 'remove'}:
        raise RuntimeError('root and fixed action required')
    # Directory is provisioned root-owned mode0755 by the candidate playbook.
    trusted(BASE / 'rules.nft')
    expected = trusted(BASE / 'expected-table.sha256').strip()
    if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        raise RuntimeError('invalid expected table digest')
    with open('/run/lock/nautobot-backend.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if sys.argv[1] == 'check':
            verify(table(), expected)
        elif sys.argv[1] == 'apply':
            apply(trusted(BASE / 'rules.nft'), expected)
        else:
            remove(expected)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('BACKEND_GUARD_FAILED: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
