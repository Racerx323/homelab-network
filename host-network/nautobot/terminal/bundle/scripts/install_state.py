#!/usr/bin/env python3
"""Fixed first-install journal and guarded acceptance. No remote orchestration."""
import fcntl
import hashlib
import json
import tempfile
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_guard as guard
from rollback_install import ALLOWED
import guard_checks as checks

BASE = Path('/var/lib/nautobot-backend-install')


def write(value):
    fd, name = tempfile.mkstemp(prefix='state-', dir=BASE)
    temp = Path(name)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(value, f);f.flush();os.fsync(f.fileno())
    os.replace(temp, BASE / 'state.json')


def main(action):
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    checks.identity()
    state_file = BASE / 'state.json'
    if action == 'prepare':
        if state_file.exists():
            raise RuntimeError('existing operation state')
        expected = json.loads(guard.trusted(BASE / 'inputs.json'))
        if set(expected['files']) != ALLOWED or expected['baseline'] != 'all_owned_files_absent':
            raise RuntimeError('unexpected installation manifest')
        if any(Path(x).exists() or Path(x).is_symlink() for x in ALLOWED):
            raise RuntimeError('existing artifact; first-install contract only')
        if guard.table() is not None or guard.run(['/usr/bin/ss','-H','-ltn','sport','=',':8080']).strip():
            raise RuntimeError('guard/listener already present')
        for unit in ['nautobot-backend-guard.service', 'nautobot-backend-install-rollback.timer', 'nautobot-backend-install-rollback.service']:
            if guard.run(['systemctl', 'show', unit, '-p', 'LoadState', '--value']).strip() != 'not-found':
                raise RuntimeError('pre-existing owned unit')
        checks.stopped()
        expected['boot_id'] = checks.identity()
        expected['unrelated_digest'] = checks.unrelated()
        expected['status'] = 'prepared'
        write(expected)
    elif action == 'report':
        value = json.loads(guard.trusted(state_file))
        if value['status'] == 'accepted':
            checks.installed(value)
            if guard.run(['systemctl', 'show', 'nautobot-backend-install-rollback.timer', '-p', 'ActiveState', '--value']).strip() != 'inactive':
                raise RuntimeError('watchdog still active')
        print(json.dumps({'status': value['status'], 'boot_matches': value['boot_id'] == checks.identity(),
                          'recovery_errors': value.get('recovery_errors', [])}))
    elif action == 'accept':
        value = json.loads(guard.trusted(state_file))
        if value['status'] != 'prepared':
            raise RuntimeError('not pending')
        checks.installed(value)
        value['status'] = 'accepted'
        write(value)
        guard.run(['systemctl','stop','nautobot-backend-install-rollback.timer'])
    else:
        raise ValueError('invalid action')


if __name__ == '__main__':
    try:
        with open(BASE / 'lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            main(sys.argv[1])
    except Exception as exc:
        print('GUARD_INSTALL_FAILED: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
