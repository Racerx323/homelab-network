#!/usr/bin/env python3
"""Candidate first-install rollback; fail closed on listener or artifact drift."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_guard as guard

STATE = Path('/var/lib/nautobot-backend-install/state.json')
ALLOWED = {
    '/usr/local/lib/nautobot-network/backend_guard.py',
    '/usr/local/lib/nautobot-network/network_policy.py',
    '/etc/nautobot-backend/rules.nft', '/etc/nautobot-backend/expected-table.sha256',
    '/etc/systemd/system/nautobot-backend-guard.service',
    '/etc/systemd/system/user@999.service.d/50-nautobot-network.conf',
    '/etc/sudoers.d/nautobot-network',
}


def rollback(state, runner=guard.run):
    if state.get('baseline') != 'all_owned_files_absent' or set(state['files']) != ALLOWED:
        raise RuntimeError('unsupported rollback baseline')
    # Validate all before any unlink; changes require manual recovery.
    for name, expected in state['files'].items():
        path = Path(name)
        if path.exists() and (path.is_symlink() or path.stat().st_uid != 0 or
                              hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise RuntimeError('artifact drift')
    guard.remove(state['table_digest'])  # refuses any8080 listener
    if Path('/etc/systemd/system/nautobot-backend-guard.service').exists():
        runner(['systemctl', 'disable', '--now', 'nautobot-backend-guard.service'])
    for name in state['files']:
        Path(name).unlink(missing_ok=True)
    runner(['systemctl', 'daemon-reload'])
    # Preserve protected operation evidence/helper for review, not silent cleanup.


def recover(state):
    if state.get('status') not in {'accepted', 'rolled_back'}:
        import install_state
        import guard_checks as checks
        try:
            if checks.identity() != state['boot_id']:
                raise RuntimeError('boot changed')
            checks.unrelated()
            rollback(state)
            if any(Path(x).exists() or Path(x).is_symlink() for x in ALLOWED):
                raise RuntimeError('rollback residue')
            if guard.table() is not None:
                raise RuntimeError('owned table remains')
            checks.unrelated()
            checks.stopped()
            state['status'] = 'rolled_back'
            state['recovery_errors'] = []
            install_state.write(state)
            guard.run(['systemctl', 'stop', 'nautobot-backend-install-rollback.timer'])
        except Exception as exc:
            state['status'] = 'manual_intervention'
            state['recovery_errors'] = [type(exc).__name__ + ': ' + str(exc)[:200]]
            install_state.write(state)
            raise


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise RuntimeError('root required')
        with open(STATE.parent / 'lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = json.loads(guard.trusted(STATE))
            recover(state)
    except Exception as exc:
        print('GUARD_ROLLBACK_MANUAL_REVIEW: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
