#!/usr/bin/env python3
"""Narrow candidate route transaction. Executed by the owner playbook only."""
import json
import tempfile
import os
from pathlib import Path
import subprocess
import sys
import fcntl
import hashlib
import base64
import stat
import configparser
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_policy import load_policy, route_commands

BASE = Path('/var/lib/nautobot-proxy-route')


class CommandFailure(RuntimeError):
    def __init__(self, args, rc, stderr='', timed_out=False):
        # Only ip stderr is retained verbatim: nmcli may report profile content.
        safe = ''.join(c for c in stderr if c in '\n\t' or 32 <= ord(c) < 127)[:2048]
        self.record = {'argv': args, 'returncode': rc, 'timed_out': timed_out,
                       'stderr': safe if args[0] == 'ip' else '[suppressed for non-ip command]'}
        super().__init__(json.dumps(self.record, sort_keys=True))


def run(args, timeout=25):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired:
        raise CommandFailure(args, None, timed_out=True) from None
    if r.returncode:
        raise CommandFailure(args, r.returncode, r.stderr)
    return r.stdout.strip()


def settle_route(p, host, expected_addresses, call=run, clock=time.monotonic,
                 sleep=time.sleep, record=lambda value: None, seconds=20):
    deadline = clock() + seconds
    samples = []
    stable = 0
    while clock() < deadline and len(samples) < 20:
        def probe(args):
            if call is run:
                return run(args, timeout=max(.01, min(2, deadline-clock())))
            return call(args)
        item = {'elapsed_seconds': round(seconds - (deadline-clock()), 3)}
        try:
            route = json.loads(probe(['ip', '-6', '-j', 'route', 'get', p['destination6']]))
            addresses = json.loads(probe(['ip', '-j', 'address', 'show', 'dev', p['interface']]))
            routes = json.loads(probe(['ip', '-6', '-j', 'route', 'show', 'table', 'all']))
            info = [x for row in addresses for x in row.get('addr_info', [])]
            item['source_matches'] = len(route) == 1 and route[0].get('prefsrc', route[0].get('src')) == p['proxies'][host]['ipv6']
            item['addresses_match'] = sorted(x['local'] for x in info) == expected_addresses
            item['dad_complete'] = all(not x.get('tentative') and not x.get('dadfailed') for x in info)
            item['owned_route_present'] = any(x.get('dst', '').split('/')[0] == p['destination6'] and x.get('dev') == p['interface'] for x in routes)
            good = all(item[k] for k in ['source_matches','addresses_match','dad_complete','owned_route_present'])
        except CommandFailure as exc:
            item['command_failure'] = exc.record
            good = False
        except (ValueError, KeyError, TypeError) as exc:
            item['invalid_evidence'] = type(exc).__name__
            samples.append(item);record(samples)
            raise RuntimeError('invalid route-settlement evidence') from None
        stable = stable + 1 if good else 0
        item['consecutive_matches'] = stable
        samples.append(item);record(samples)
        if stable >= 3 and clock() <= deadline:
            return samples
        if clock() < deadline:
            sleep(min(1, deadline-clock()))
    raise RuntimeError('route settlement timed out; retained samples explain failed checks')


def write_state(value):
    fd, name = tempfile.mkstemp(prefix='state-', dir=BASE)
    tmp = Path(name)
    with os.fdopen(fd, 'w') as f:
        os.chmod(tmp, 0o600)
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, BASE / 'state.json')


def selected(p):
    rows = json.loads(run(['ip', '-6', '-j', 'route', 'get', p['destination6']]))
    if len(rows) != 1:
        raise RuntimeError('ambiguous route')
    return rows[0].get('prefsrc', rows[0].get('src'))


def find_profile(uuid):
    matches = []
    for path in Path('/etc/NetworkManager/system-connections').iterdir():
        if path.is_symlink() or not path.is_file():
            continue
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(path.read_text())
        except (UnicodeError, configparser.Error):
            continue
        if parser.get('connection', 'uuid', fallback=None) == uuid:
            matches.append(str(path))
    if len(matches) != 1:
        raise RuntimeError('unique persistent profile required')
    return matches[0]


def profile_snapshot(filename):
    path = Path(filename)
    if path.parent != Path('/etc/NetworkManager/system-connections') or path.is_symlink():
        raise RuntimeError('unexpected profile file')
    st = path.stat()
    if st.st_uid != 0 or not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise RuntimeError('unsafe profile metadata')
    raw = path.read_bytes()
    return {'path': str(path), 'data': base64.b64encode(raw).decode(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'mode': stat.S_IMODE(st.st_mode),
            'uid': st.st_uid, 'gid': st.st_gid, 'atime_ns': st.st_atime_ns, 'mtime_ns': st.st_mtime_ns}


def profile_without_route(raw):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(raw.decode())
    return {section: {k: v for k, v in parser[section].items()
                      if not (section == 'ipv6' and k.startswith('route')) and
                      not (section == 'connection' and k == 'timestamp')}
            for section in parser.sections()}


def restore_profile(snapshot, after_hash=None):
    path = Path(snapshot['path'])
    now = profile_snapshot(str(path))
    original = base64.b64decode(snapshot['data'])
    if now['sha256'] == snapshot['sha256']:
        return
    if after_hash:
        if now['sha256'] != after_hash:
            raise RuntimeError('concurrent profile change')
    elif profile_without_route(path.read_bytes()) != profile_without_route(original):
        raise RuntimeError('partial write changed unrelated profile fields')
    tmp = path.with_name(path.name + '.nautobot-rollback')
    with open(tmp, 'xb') as f:
        os.fchmod(f.fileno(), snapshot['mode'])
        os.fchown(f.fileno(), snapshot['uid'], snapshot['gid'])
        f.write(original); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    os.utime(path, ns=(snapshot['atime_ns'], snapshot['mtime_ns']))
    if profile_snapshot(str(path))['sha256'] != snapshot['sha256']:
        raise RuntimeError('profile restore mismatch')


def transaction(action, p, host, uuid, call=run, save=write_state, root=BASE, snapshot=profile_snapshot, restore=restore_profile, locate=find_profile):
    commands = route_commands(p, host, uuid)
    if host != 'pihole00' or uuid != '3078e1cc-2e08-3745-b5e4-a60426628c39':
        raise RuntimeError('only qualified standby profile supported')
    if call(['nmcli', '--version']) != 'nmcli tool, version 1.42.4':
        raise RuntimeError('NetworkManager version drift')
    actual_host = call(['hostname', '-s'])
    if actual_host != {'pihole0': 'j1-svpihole0', 'pihole00': 'j1-svpihole00'}[host]:
        raise RuntimeError('wrong host')
    active = call(['nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', p['interface']])
    if active != uuid:
        raise RuntimeError('wrong active profile')
    query = ['nmcli', '-g', 'ipv6.routes', 'connection', 'show', 'uuid', uuid]
    saved = root / 'state.json'
    if action == 'report':
        value = json.loads(saved.read_text())
        print(json.dumps({'status': value['status'], 'host': value['host'],
                          'uuid': value['uuid'], 'profile_before_sha256': value['profile']['sha256'],
                          'profile_after_sha256': value.get('profile_after_hash')}))
        return
    if action == 'apply' and saved.exists() and json.loads(saved.read_text()).get('status') == 'accepted':
        action = 'accept'  # verify accepted identity without reapplying
    if action == 'expire' and not saved.exists():
        return  # timeout before mutation/state creation
    if action in {'accept', 'expire'}:
        existing = json.loads(saved.read_text())
        if existing['host'] != host or existing['uuid'] != uuid:
            raise RuntimeError('state identity mismatch')
        if action == 'expire' and existing['status'] in {'accepted', 'rolled_back'}:
            return
        if action == 'accept':
            if existing['status'] not in {'pending_acceptance', 'accepted'}:
                raise RuntimeError('not pending acceptance')
            if call(['cat', '/proc/sys/kernel/random/boot_id']) != existing['boot_id']:
                raise RuntimeError('boot changed before acceptance')
            if call(query) != existing['after']:
                raise RuntimeError('profile changed before acceptance')
            if snapshot(existing['profile']['path'])['sha256'] != existing['profile_after_hash']:
                raise RuntimeError('profile file changed before acceptance')
            rows = json.loads(call(['ip', '-6', '-j', 'route', 'get', p['destination6'],
                                    'uid', call(['id', '-u', 'caddy'])]))
            if len(rows) != 1 or rows[0].get('prefsrc', rows[0].get('src')) != p['proxies'][host]['ipv6']:
                raise RuntimeError('Caddy preferred source drift')
            now = json.loads(call(['ip', '-j', 'address', 'show', 'dev', p['interface']]))
            if sorted(x['local'] for row in now for x in row.get('addr_info', [])) != existing['addresses_before']:
                raise RuntimeError('address drift before acceptance')
            existing['status'] = 'accepted'
            save(existing)
            call(['systemctl', 'stop', 'nautobot-proxy-route-retry-rollback.timer'])
            return
        action = 'rollback'
    if action == 'apply':
        if saved.exists():
            raise RuntimeError('existing operation requires explicit reconciliation')
        before = call(query)
        routes = json.loads(call(['ip', '-6', '-j', 'route', 'show', 'table', 'all']))
        if p['destination6'] in before or any(x.get('dst', '').split('/')[0] == p['destination6'] for x in routes):
            raise RuntimeError('existing destination route')
        addresses = json.loads(call(['ip', '-6', '-j', 'address', 'show', 'dev', p['interface']]))
        valid = [x for row in addresses for x in row.get('addr_info', [])
                 if x.get('local') == p['proxies'][host]['ipv6'] and not x.get('tentative') and not x.get('dadfailed')]
        if len(valid) != 1:
            raise RuntimeError('permanent source unavailable')
        # First operation is standby only; refuse VIP ownership instead of moving it.
        all_addresses = json.loads(call(['ip', '-j', 'address', 'show', 'dev', p['interface']]))
        present = {x['local'] for row in all_addresses for x in row.get('addr_info', [])}
        if present & {'10.1.0.55', '10.1.0.56', 'fd36:5aa8:6971:1::55', 'fd36:5aa8:6971:1::56'}:
            raise RuntimeError('standby required')
        profile = snapshot(locate(uuid))
        state = {'profile': profile, 'boot_id': call(['cat', '/proc/sys/kernel/random/boot_id']), 'addresses_before': sorted(present), 'host': host, 'uuid': uuid, 'before': before, 'status': 'prepared'}
        save(state)  # persisted before any profile change
        call(commands['apply'])
        state['after'] = call(query)
        state['profile_after_hash'] = snapshot(profile['path'])['sha256']
        state['status'] = 'modified'
        save(state)
        call(commands['reapply'])
        def retain(samples):
            state['settlement'] = samples
            save(state)
        settle_route(p, host, state['addresses_before'], call=call, record=retain)
        state['status'] = 'pending_acceptance'
        save(state)
    elif action == 'rollback':
        state = json.loads(saved.read_text())
        if state['host'] != host or state['uuid'] != uuid:
            raise RuntimeError('state identity mismatch')
        current = call(query)
        if state.get('after') is not None and current not in {state['before'], state['after']}:
            raise RuntimeError('concurrent route-property change')
        if state.get('after') is None and current != state['before']:
            # Interrupted after nmcli write: remove only our tuple, then verify
            # the previous property before restoring exact profile bytes.
            call(commands['remove'])
            if call(query) != state['before']:
                raise RuntimeError('partial-write route drift')
            state.pop('profile_after_hash', None)
        restore(state['profile'], state.get('profile_after_hash'))
        call(['nmcli', 'connection', 'load', state['profile']['path']])
        call(commands['reapply'])
        if call(query) != state['before']:
            raise RuntimeError('rollback profile drift: manual review required')
        rows = json.loads(call(['ip', '-6', '-j', 'route', 'show', 'table', 'all']))
        if any(x.get('dst', '').split('/')[0] == p['destination6'] for x in rows):
            raise RuntimeError('rollback runtime route remains')
        state['status'] = 'rolled_back'
        save(state)
    else:
        raise ValueError('invalid action')


if __name__ == '__main__':
    try:
        if os.geteuid() != 0 or len(sys.argv) != 4:
            raise RuntimeError('root action host uuid required')
        os.umask(0o077)
        BASE.mkdir(mode=0o700, exist_ok=True)
        if BASE.is_symlink() or BASE.stat().st_uid != 0 or BASE.stat().st_mode & 0o077:
            raise RuntimeError('unsafe state directory')
        with open(BASE / 'lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            policy = load_policy(Path('/etc/nautobot-proxy-route/policy.json'))
            transaction(sys.argv[1], policy, sys.argv[2], sys.argv[3])
    except Exception as exc:
        if isinstance(exc, CommandFailure):
            diagnostic = BASE / 'command-failure.json'
            diagnostic.write_text(json.dumps(exc.record, indent=2))
            diagnostic.chmod(0o600)
        print('PROXY_ROUTE_FAILED: ' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
