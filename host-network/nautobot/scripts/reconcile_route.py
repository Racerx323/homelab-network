#!/usr/bin/env python3
"""Verify consumed rolled-back inputs and archive them before new helper staging."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

BASE = Path('/var/lib/nautobot-proxy-route')
ARCHIVE = Path('/var/lib/nautobot-proxy-route-archive')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def secure(path, mode=None, uid=0):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('symlink refused')
    s = path.stat()
    if s.st_uid != uid or s.st_gid != uid or (mode is not None and stat.S_IMODE(s.st_mode) != mode):
        raise RuntimeError('unsafe metadata')
    return s


def validate(state, contract, current_profile):
    if {k: v for k, v in state.items() if k != 'profile'} != contract['state']:
        raise RuntimeError('retained state drift')
    profile = state['profile']
    if profile['path'] != contract['profile_path']:
        raise RuntimeError('profile path drift')
    if profile['sha256'] != contract['profile_sha256'] or digest(base64.b64decode(profile['data'], validate=True)) != profile['sha256']:
        raise RuntimeError('retained profile mismatch')
    if digest(current_profile) != profile['sha256']:
        raise RuntimeError('current profile differs from rollback')


def archive(contract, base=BASE, archive_root=ARCHIVE, uid=0, profile_parent=Path('/etc/NetworkManager/system-connections')):
    secure(base, 0o700, uid)
    if {p.name for p in base.iterdir()} != {'state.json', 'lock'}:
        raise RuntimeError('unexpected retained files')
    secure(base/'state.json', 0o600, uid)
    secure(base/'lock', 0o600, uid)
    with (base/'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads((base/'state.json').read_text())
        profile = Path(state['profile']['path'])
        if profile.parent != profile_parent:
            raise RuntimeError('unexpected profile path')
        secure(profile, state['profile']['mode'], uid)
        validate(state, contract, profile.read_bytes())
        for name, expected in contract['files'].items():
            path = Path(name)
            secure(path, 0o644, uid)
            if digest(path.read_bytes()) != expected:
                raise RuntimeError('retained helper drift')
        archive_root.mkdir(mode=0o700, exist_ok=True)
        secure(archive_root, 0o700, uid)
        dest = archive_root / contract['consumed_bundle']
        dest.mkdir(mode=0o700)  # Existing archive means stop; no implicit rerun.
        hashes = {}
        for name in contract['files']:
            target = dest / Path(name).name
            shutil.copyfile(name, target)
            target.chmod(0o600)
            hashes[target.name] = digest(target.read_bytes())
            if hashes[target.name] != contract['files'][name]:
                raise RuntimeError('archive copy mismatch')
        raw = (base/'state.json').read_bytes()
        (dest/'state.sha256').write_text(digest(raw)+'\n')
        # Atomic rename preserves the raw profile backup and lock as-is.
        os.rename(base, dest/'state')
        if digest((dest/'state/state.json').read_bytes()) != digest(raw):
            raise RuntimeError('archive state verification failed')
        print(json.dumps({'archived': str(dest), 'state_sha256': digest(raw), 'files': hashes}))


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    contract = json.loads(base64.b64decode(sys.argv[1], validate=True))
    for unit in ('nautobot-proxy-route-rollback.timer', 'nautobot-proxy-route-rollback.service'):
        out = subprocess.run(['systemctl','show',unit,'-p','ActiveState','--value'],
                             capture_output=True,text=True,check=True,timeout=5).stdout.strip()
        if out != 'inactive':
            raise RuntimeError('predecessor recovery unit still active or unavailable')
    archive(contract)


if __name__ == '__main__':
    main()
