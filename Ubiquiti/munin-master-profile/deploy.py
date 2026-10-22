"""Sealed svmf network transaction: local controller and detached target worker.

No target contact during seal/tests. Execute consumes a bundle exactly once.
The controller can inspect an interrupted operation, but cannot replay or restore it.
"""
import argparse
import hashlib
import http.client
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent
STATE = Path('/var/lib/svmf-network')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
NTP_NAME = 'ntp1.local.theama.co'
NTP_ADDRESSES = ['10.1.0.51', 'fd36:5aa8:6971:1::51']
TERMINAL = {'committed', 'rolled_back', 'recovery_held', 'preflight_failed'}
MEMBERS = {'deploy.py', 'guard.py', 'static-settings.json', 'spec.json', 'known_hosts',
           'tls_probe.py', 'ca.pem'}


def encoded(value):
    return (json.dumps(value, sort_keys=True)+'\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private(path, directory=False):
    root_owner = Path('/').lstat().st_uid
    for parent in (path, *path.parents):
        info = parent.lstat()
        if parent == Path('/tmp') and info.st_uid == root_owner and info.st_mode & stat.S_ISVTX:
            break
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (root_owner, os.geteuid()) or info.st_mode & 0o022:
            raise ValueError('unsafe private path ancestry')
        if parent == path and ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)) or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('private regular file/directory required')
        if parent == Path('/var/lib') or parent == Path('/tmp'):
            break


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync_dir(path.parent)


def save(path, value):
    temporary = path.with_name('.'+path.name+'.'+secrets.token_hex(8))
    write_new(temporary, encoded(value))
    os.replace(temporary, path); sync_dir(path.parent)


def command(argv, timeout=12, label=None):
    name = label or Path(argv[0]).name
    try:
        result = subprocess.run(argv, env=ENV, capture_output=True, timeout=70 if '--wait' in argv else timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('bounded command timed out: '+name) from error
    if result.returncode or len(result.stdout) > 262144 or len(result.stderr) > 65536:
        raise RuntimeError('bounded command failed: '+name+'; exit='+str(result.returncode)
                           +'; stdout_bytes='+str(len(result.stdout))+'; stderr_bytes='+str(len(result.stderr)))
    return result.stdout.decode().strip()


def properties(raw):
    result = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(':')
        if not sep or key in result:
            raise ValueError('duplicate or malformed profile property')
        result[key] = '' if value.strip() == '--' else value.strip()
    return result


def effective(spec):
    return properties(command(['/usr/bin/nmcli', '-m', 'multiline', '-f',
        'connection,802-3-ethernet,ipv4,ipv6,proxy', 'connection', 'show', 'uuid', spec['uuid']]))


def unit(name):
    result = dict(line.split('=', 1) for line in command(['/usr/bin/systemctl', 'show', name,
        '--property=MainPID,InvocationID,NRestarts,ActiveState,SubState']).splitlines())
    if result.get('ActiveState') != 'active' or result.get('SubState') != 'running' or not int(result.get('MainPID', '0')):
        raise ValueError('required service inactive: '+name)
    return result


def identity(spec):
    if (os.geteuid() != 0 or socket.gethostname() != spec['hostname']
            or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != spec['boot_id']
            or Path('/sys/class/net', spec['interface'], 'address').read_text().strip() != spec['mac']
            or command(['/usr/bin/nmcli', '--version']) != spec['nm_version']):
        raise ValueError('root/host/boot/MAC/version drift')
    for record in spec.get('identity_file_metadata', []):
        info = Path(record['path']).lstat()
        actual = {'path': record['path'], 'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid,
                  'inode': info.st_ino, 'size': info.st_size, 'mtime_ns': info.st_mtime_ns}
        if actual != record or not stat.S_ISREG(info.st_mode):
            raise ValueError('address-generation identity metadata drift')
    active = command(['/usr/bin/nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active'])
    if [r for r in active.splitlines() if r.endswith(':'+spec['interface'])] != [spec['uuid']+':'+spec['interface']]:
        raise ValueError('active UUID drift')
    names = command(['/usr/bin/nmcli', '-t', '-f', 'UUID,FILENAME', 'connection', 'show'])
    if [r.partition(':')[2] for r in names.splitlines() if r.partition(':')[0] == spec['uuid']] != [spec['profile']]:
        raise ValueError('persistent filename drift')
    return {name: unit(name) for name in spec['units']}


def http_get(address, port, path, host):
    client = http.client.HTTPConnection(address, port, timeout=3)
    try:
        client.request('GET', path, headers={'Host': host, 'Connection': 'close'})
        response = client.getresponse()
        body = response.read(65537)
        if response.status != 200 or len(body) > 65536 or not body:
            raise ValueError('HTTP health failed')
        return {'status': response.status, 'body_sha256': sha(body)}
    finally:
        client.close()


def valid_dashboard(spec, address, rows):
    if (not isinstance(rows, list) or len(rows) != 3
            or {r.get('path') for r in rows} != set(spec['dashboard_paths'])):
        raise ValueError('exact HTTPS root/CSS/PNG proof required')
    for row in rows:
        kind = 'image/png' if row['path'].endswith('.png') else 'text/css' if row['path'].endswith('.css') else 'text/html'
        if (row.get('address') != address or row.get('tls_verified') is not True
                or row.get('status') != 200 or row.get('response_ok') is not True
                or row.get('leaf_sha256') != spec['dashboard_leaf_sha256']
                or row.get('content_type') != kind
                or kind == 'image/png' and row.get('png_signature') is not True):
            raise ValueError('HTTPS dashboard proof failed')


def dashboard_https(spec, directory, address):
    for name in ('tls_probe.py', 'ca.pem'):
        if sha((directory/name).read_bytes()) != spec['members'][name]:
            raise ValueError('frozen HTTPS input mismatch')
    loader = importlib.util.spec_from_file_location('dashboard_tls', directory/'tls_probe.py')
    helper = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(helper)
    if helper.HOST != spec['dashboard_host']:
        raise ValueError('dashboard TLS/Host identity drift')
    context = ssl.create_default_context(cadata=(directory/'ca.pem').read_text(encoding='ascii'))
    rows = [helper.request(address, path, context)[0] for path in spec['dashboard_paths']]
    valid_dashboard(spec, address, rows)
    return rows


def smtp_banner(address, port):
    with socket.create_connection((address, port), timeout=3) as stream:
        with stream.makefile('rb') as reader:
            banner = reader.readline(513)
            if not banner.startswith(b'220 ') or len(banner) > 512:
                raise ValueError('SMTP greeting failed')
            stream.sendall(b'QUIT\r\n')
            if not reader.readline(513).startswith(b'221 '):
                raise ValueError('SMTP QUIT failed')
    return sha(banner)


def resolver_addresses(raw, family, expected):
    """Require the exact native endpoint; mapped IPv4 never proves IPv6 DNS."""
    values = set()
    try:
        for line in raw.splitlines():
            fields = line.split()
            if not 2 <= len(fields) <= 3 or fields[1] not in ('STREAM', 'DGRAM', 'RAW'):
                raise ValueError('unexpected resolver row')
            address = ipaddress.ip_address(fields[0])
            if address.version != family or (family == 6 and address.ipv4_mapped is not None):
                raise ValueError('non-native resolver family')
            values.add(str(address))
        if values != {str(ipaddress.ip_address(expected))}:
            raise ValueError('unexpected resolver endpoint')
    except ValueError as error:
        raise ValueError('resolver IPv'+str(family)+': '+str(error)) from error
    return sorted(values)


def system_resolver(spec, family):
    raw = command(['/usr/bin/getent', 'ahostsv'+str(family), spec['resolver_name']],
                  label='getent IPv'+str(family)+' '+spec['resolver_name'])
    return resolver_addresses(raw, family, spec['ntp_addresses'][0 if family == 4 else 1])


def snapshot(spec):
    services = identity(spec)
    addresses = json.loads(command(['/usr/sbin/ip', '-j', 'address', 'show', 'dev', spec['interface']]))[0]['addr_info']
    routes = [json.loads(command(['/usr/sbin/ip', family, '-j', 'route', 'get', dest]))[0]
              for family, dest in zip(('-4', '-6'), spec['ntp_addresses'])]
    defaults = [json.loads(command(['/usr/sbin/ip', family, '-j', 'route', 'show', 'default', 'dev', spec['interface']]))
                for family in ('-4', '-6')]
    runtime = properties(command(['/usr/bin/nmcli', '-m', 'multiline', '-f', 'IP4,IP6', 'device', 'show', spec['interface']]))
    resolver = system_resolver(spec, 4)
    resolver6 = system_resolver(spec, 6)
    resolver_config = {'nameserver': [], 'search': []}
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        parts = line.split('#', 1)[0].split()
        if parts and parts[0] in resolver_config:
            resolver_config[parts[0]].extend(parts[1:])
    # This checks existing published endpoints without assuming Podman ownership.
    application = http_get('127.0.0.1', spec['apprise_port'], '/status', 'localhost')
    smtp = smtp_banner('127.0.0.1', spec['mailrise_port'])
    return {'services': services, 'addresses': addresses, 'routes': routes, 'defaults': defaults,
            'runtime': runtime, 'resolver4': resolver, 'resolver6': resolver6,
            'apprise': application['status'], 'smtp_banner': smtp, 'effective': effective(spec),
            'resolver_config': resolver_config, 'monotonic': time.monotonic()}


def checks(spec, before, now, candidate):
    settings = spec['settings']
    stable = lambda values: {k: v for k, v in values.items()
        if k not in settings and k != 'connection.timestamp'}
    addr = {a['local']: a for a in now['addresses']}
    old = {a['local'] for a in before['addresses'] if not a.get('temporary')}
    want = spec['addresses'] if candidate else spec['original_sources']
    expected = settings if candidate else {k: before['effective'][k] for k in settings}
    runtime = now['runtime']
    dns = [{v for k, v in runtime.items() if k.startswith(prefix)} for prefix in ('IP4.DNS[', 'IP6.DNS[')]
    global6 = {a['local'] for a in before['addresses'] if a.get('scope') == 'global'
        and ':' in a['local'] and not ipaddress.ip_address(a['local']) in ipaddress.ip_network('fc00::/7')}
    good_routes = (all(r.get('dev') == spec['interface'] and r.get('prefsrc') == source
                       for r, source in zip(now['routes'], want))
        and any(r.get('gateway') == spec['gateway4'] for r in now['defaults'][0])
        and any(r.get('protocol') == 'ra' and r.get('gateway', '').startswith('fe80:') for r in now['defaults'][1])
        and bool(global6) and global6 <= set(addr)
        and old <= set(addr))
    return {'address4': want[0] in addr and addr[want[0]].get('prefixlen') == 22,
        'address6': want[1] in addr and addr[want[1]].get('prefixlen') == 64,
        'routes': good_routes,
        'dns': (dns == [{spec['dns'][0]}, {spec['dns'][1]}]
                and set(now['resolver_config']['nameserver']) == set(spec['dns'])
                and now['resolver_config']['search'] == [spec['search']]
                and now['resolver4'] == before['resolver4'] == [spec['ntp_addresses'][0]]
                and now['resolver6'] == before['resolver6'] == [spec['ntp_addresses'][1]]),
        'dad': all(not a.get('tentative') and not a.get('dadfailed') for a in now['addresses']),
        'service_continuity': (now['services'] == before['services'] and now['apprise'] == 200
            and now['smtp_banner'] == before['smtp_banner']
            and stable(now['effective']) == stable(before['effective'])
            and all(now['effective'].get(k) == v for k, v in expected.items()))}


def guard_module():
    loader = importlib.util.spec_from_file_location('svmf_guard', ROOT/'guard.py')
    module = importlib.util.module_from_spec(loader); loader.loader.exec_module(module)
    return module


def record(directory, state, phase, **fields):
    state.update(phase=phase, updated=time.time(), **fields)
    save(directory/'state.json', state)


def valid_observations(spec, state, proof):
    if proof.get('bundle_sha256') != state['bundle_sha256'] or proof.get('challenge') != state['challenge']:
        raise ValueError('confirmation identity mismatch')
    observations = proof.get('observations', [])
    if len(observations) != 2 or [x.get('family') for x in observations] != [4, 6]:
        raise ValueError('both independent SSH families required')
    for observation in observations:
        if (observation.get('challenge') != state['challenge']
                or not 0 <= time.monotonic()-observation['snapshot']['monotonic'] <= 25
                or not all(checks(spec, state['before'], observation['snapshot'], True).values())):
            raise ValueError('stale or failed independent observation')
        valid_dashboard(spec, spec['addresses'][0 if observation['family'] == 4 else 1], observation.get('dashboard'))


def profile_record(spec):
    path = Path(spec['profile'])
    private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno()); raw = stream.read(262145)
        after = os.fstat(stream.fileno())
    stable = lambda item: tuple(getattr(item, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o077 or len(raw) > 262144 or stable(info) != stable(after) or stable(info) != stable(path.lstat())):
        raise ValueError('root-private stable bounded profile required')
    return raw, {'sha256': sha(raw), 'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'size': info.st_size, 'inode': info.st_ino,
                 'device': info.st_dev, 'mtime_ns': info.st_mtime_ns}


def worker(directory):
    spec = json.loads((directory/'spec.json').read_bytes())
    state = json.loads((directory/'state.json').read_bytes())
    if state.get('phase') != 'staged':
        raise ValueError('worker may start once only; inspect interrupted state')
    guard = guard_module().Checkpoint(spec['interface'], spec['uuid'], spec['settings'], spec['checkpoint_seconds'], command)
    try:
        record(directory, state, 'preflight')
        raw, metadata = profile_record(spec)
        if sha(raw) != spec['profile_sha256'] or any(metadata.get(k) != v for k, v in spec.get('profile_metadata', {}).items()):
            raise ValueError('exact original profile baseline drift')
        before = snapshot(spec)
        if before['services']['NetworkManager.service'] != spec['manager']:
            raise ValueError('accepted manager identity drift')
        if any(before['effective'].get(k) != v for k, v in spec.get('original_selected', {}).items()):
            raise ValueError('accepted original effective settings drift')
        if not all(checks(spec, before, before, False).values()):
            raise ValueError('original network/application preconditions failed')
        write_new(directory/'original.nmconnection', raw)
        record(directory, state, 'backup_durable', before=before,
               backup=metadata, challenge=secrets.token_hex(32))
        if snapshot(spec)['effective'] != before['effective'] or profile_record(spec)[0] != raw:
            raise ValueError('pre-arm profile drift')
        record(directory, state, 'arming')
        guard.begin()
        record(directory, state, 'guarded', checkpoint=guard.path, device=guard.device,
               original=guard.original, deadline=guard.deadline)
        record(directory, state, 'write_intent')
        guard.apply()
        record(directory, state, 'awaiting_confirmation')
        # Native timer remains responsible if either process is killed. No replay.
        while time.monotonic() < guard.deadline-45:
            if (directory/'confirmation.json').exists():
                proof = json.loads((directory/'confirmation.json').read_bytes())
                valid_observations(spec, state, proof)
                def accept():
                    current = snapshot(spec)
                    result = checks(spec, before, current, True)
                    if time.monotonic() >= guard.deadline-35:
                        raise ValueError('final confirmation reserve exhausted')
                    return dict(result, peer4=True, peer6=True)
                record(directory, state, 'commit_intent')
                guard.commit(accept)
                record(directory, state, 'committed', acceptance=proof)
                return
            time.sleep(1)
        raise ValueError('independent confirmation deadline')
    except Exception as error:
        previous = state['phase']
        record(directory, state, 'failure', phase_before_failure=previous, error=type(error).__name__+': '+str(error))
        if not guard.path:
            # begin may have created an unrecorded checkpoint before raising;
            # never infer absence or destroy an unidentified checkpoint.
            phase = 'recovery_held' if state['phase_before_failure'] == 'arming' else 'preflight_failed'
            record(directory, state, phase)
            return
        try:
            if identity(spec) != state['before']['services']:
                raise ValueError('service/manager identity drift; retain native guard')
            current = effective(spec)
            stable = lambda x: {k: v for k, v in x.items() if k not in spec['settings'] and k != 'connection.timestamp'}
            selected = {k: current.get(k) for k in spec['settings']}
            original = {k: state['before']['effective'].get(k) for k in spec['settings']}
            if stable(current) != stable(state['before']['effective']) or selected not in (original, spec['settings']):
                raise ValueError('foreign profile drift; recovery held')
            if guard.phase == 'committed':
                raise ValueError('commit completed but durable receipt failed; inspect only')
            guard.rollback()
            record(directory, state, 'recovering')
            deadline = time.monotonic()+60
            while time.monotonic() < deadline:
                try:
                    restored = snapshot(spec)
                    if all(checks(spec, state['before'], restored, False).values()):
                        record(directory, state, 'rolled_back', recovery=restored)
                        return
                except (RuntimeError, ValueError, OSError):
                    pass
                time.sleep(2)
            raise ValueError('recovery convergence unproven')
        except Exception as recovery_error:
            record(directory, state, 'recovery_held', recovery_error=type(recovery_error).__name__+': '+str(recovery_error))


def unpack(raw, digest, check_expiry=True):
    if sha(raw) != digest or len(raw) > 2097152:
        raise ValueError('bundle hash or size mismatch')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        entries = archive.getmembers()
        if len(entries) != len(MEMBERS) or {e.name for e in entries} != MEMBERS or any(not e.isfile() or e.size > 524288 for e in entries):
            raise ValueError('closed regular bundle member set required')
        files = {e.name: archive.extractfile(e).read() for e in entries}
    spec = json.loads(files['spec.json'])
    if spec.get('resolver_name') != NTP_NAME or spec.get('ntp_addresses') != NTP_ADDRESSES:
        raise ValueError('reviewed NTP resolver name and native endpoints required')
    if not re.fullmatch(r'svmf-network-[a-z0-9-]{1,48}', spec['operation_id']):
        raise ValueError('operation id')
    if check_expiry and (not 0 <= time.time()-spec['prepared_epoch'] <= 86400 or time.time() >= spec['expires_epoch']):
        raise ValueError('bundle expired or future dated')
    for name, digest in spec['members'].items():
        if name == 'spec.json' or name not in files or sha(files[name]) != digest:
            raise ValueError('member integrity')
    if set(spec['members']) != MEMBERS-{'spec.json'}:
        raise ValueError('closed member manifest required')
    return spec, files


def install(raw, digest):
    if os.geteuid() != 0:
        raise ValueError('root required')
    spec, files = unpack(raw, digest)
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True); private(STATE, True)
    directory = STATE/spec['operation_id']
    directory.mkdir(mode=0o700); sync_dir(STATE)  # exclusive: never replay
    for name, data in files.items():
        write_new(directory/name, data)
    save(directory/'state.json', {'phase': 'staged', 'bundle_sha256': digest,
                                 'operation_id': spec['operation_id'], 'updated': time.time()})
    write_new(directory/'worker.log', b'')
    command(['/usr/bin/systemd-run', '--quiet', '--unit='+spec['operation_id'],
        '--property=Type=exec', '--property=Restart=no', '--property=RemainAfterExit=yes',
        '--property=RuntimeMaxSec=480', '--property=UMask=0077', '--working-directory=/',
        '--property=StandardOutput=append:'+str(directory/'worker.log'),
        '--property=StandardError=append:'+str(directory/'worker.log'),
        '/usr/bin/python3', '-I', '-B', str(directory/'deploy.py'), 'worker', str(directory)])
    return {'staged': True, 'operation_id': spec['operation_id']}


def action(directory, name, proof=None):
    private(directory, True)
    state = json.loads((directory/'state.json').read_bytes())
    spec = json.loads((directory/'spec.json').read_bytes())
    if name == 'status':
        # Exact backup bytes never leave the root-private target directory.
        return {k: state[k] for k in ('phase', 'updated', 'bundle_sha256', 'operation_id', 'challenge', 'deadline') if k in state}
    if name == 'readback':
        now = snapshot(spec)
        guard = guard_module().Checkpoint(spec['interface'], spec['uuid'], spec['settings'], command=command)
        return {'state': action(directory, 'status'), 'snapshot': now, 'checkpoints': guard.checkpoints(),
            'original_checks': checks(spec, state['before'], now, False) if 'before' in state else None,
            'candidate_checks': checks(spec, state['before'], now, True) if 'before' in state else None,
            'current_profile': profile_record(spec)[1]}
    if name == 'observe':
        if state['phase'] != 'awaiting_confirmation':
            raise ValueError('observation phase')
        now = snapshot(spec)
        return {'challenge': state['challenge'], 'snapshot': now, 'checks': checks(spec, state['before'], now, True)}
    if name == 'confirm':
        if state['phase'] != 'awaiting_confirmation':
            raise ValueError('confirmation phase')
        valid_observations(spec, state, proof)
        write_new(directory/'confirmation.json', encoded(proof))
        return {'confirmation_recorded': True}
    raise ValueError('unknown remote action')


BOOTSTRAP = "import sys; raw=sys.stdin.buffer.read(2097153); import tarfile,io; a=tarfile.open(fileobj=io.BytesIO(raw)); source=a.extractfile('deploy.py').read(); import hashlib; assert hashlib.sha256(raw).hexdigest()==sys.argv[1]; ns={'__name__':'sealed_bootstrap','__file__':'/sealed/deploy.py'}; exec(source,ns); print(ns['json'].dumps(ns['install'](raw,sys.argv[1])))"


def ssh(spec, known_hosts, family, address, remote):
    ipaddress.ip_address(address)
    options = ['BatchMode=yes', 'StrictHostKeyChecking=yes', 'HostKeyAlgorithms=ssh-ed25519',
        'UpdateHostKeys=no', 'ProxyCommand=none', 'ProxyJump=none', 'ControlMaster=no',
        'ControlPath=none', 'ControlPersist=no', 'PermitLocalCommand=no', 'ClearAllForwardings=yes',
        'ForwardAgent=no', 'ForwardX11=no', 'GlobalKnownHostsFile=/dev/null',
        'UserKnownHostsFile='+str(known_hosts), 'HostKeyAlias='+spec['host_key_alias'],
        'ConnectTimeout=5', 'ServerAliveInterval=5', 'ServerAliveCountMax=1']
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-'+str(family),
            *[item for option in options for item in ('-o', option)], spec['user']+'@'+address, remote]


def transport(argv, data=b'', evidence=None):
    started = time.time_ns()
    try:
        result = subprocess.run(argv, input=data, capture_output=True, timeout=35)
    except subprocess.TimeoutExpired:
        if evidence:
            save(evidence/('ssh-'+str(started)+'.json'), {'argv': argv, 'input_sha256': sha(data), 'timeout': True})
        raise
    if evidence:
        save(evidence/('ssh-'+str(started)+'.json'), {'argv': argv, 'input_sha256': sha(data), 'returncode': result.returncode,
            'stdout': result.stdout[:262144].decode(errors='replace'), 'stderr': result.stderr[:65536].decode(errors='replace')})
    if result.returncode or len(result.stdout) > 262144 or len(result.stderr) > 65536:
        raise RuntimeError('independent SSH failed; operation must be inspected, never replayed')
    return json.loads(result.stdout)


def remote(spec, directory, family, address, name, proof=None):
    target = STATE/spec['operation_id']
    argv = ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', '-B', str(target/'deploy.py'), name, str(target)]
    return transport(ssh(spec, directory/'known_hosts', family, address, 'cd / && '+shlex.join(argv)),
                     encoded(proof) if proof else b'', evidence=directory)


def execute(directory, digest, inspect_only=False):
    private(directory, True)
    spec, files = unpack((directory/'deployment.tar').read_bytes(), digest, check_expiry=not inspect_only)
    if files['deploy.py'] != Path(__file__).read_bytes():
        raise ValueError('execute the frozen bundled controller')
    if any((directory/name).read_bytes() != files[name] for name in ('known_hosts', 'tls_probe.py', 'ca.pem')):
        raise ValueError('frozen transport input mismatch')
    if inspect_only:
        if json.loads((directory/'execution.json').read_bytes()).get('sha256') != digest:
            raise ValueError('same consumed operation required for inspection')
        # Explicit read-only continuation: never launches worker or sends confirmation.
        results = []
        for family, address in ((4, spec['addresses'][0]), (6, spec['original_sources'][1]), (6, spec['addresses'][1])):
            try:
                results.append({'family': family, 'address': address, 'readback': remote(spec, directory, family, address, 'readback')})
            except Exception as error:
                results.append({'family': family, 'address': address, 'error': type(error).__name__})
        save(directory/('inspection-'+str(time.time_ns())+'.json'), results)
        return results
    # Consume before first target contact. Failure is not authority to retry.
    write_new(directory/'execution.json', encoded({'sha256': digest, 'epoch': time.time()}))
    baseline_dashboard = [dashboard_https(spec, directory, address) for address in spec['original_sources']]
    save(directory/'baseline-dashboard.json', baseline_dashboard)
    initial = ssh(spec, directory/'known_hosts', 4, spec['addresses'][0],
        'cd / && /usr/bin/sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(BOOTSTRAP)+' '+digest)
    transport(initial, (directory/'deployment.tar').read_bytes(), evidence=directory)
    deadline = time.monotonic()+spec['checkpoint_seconds']+120
    submitted = False
    while time.monotonic() < deadline:
        try:
            status = remote(spec, directory, 4, spec['addresses'][0], 'status')
            save(directory/'controller-state.json', status)
            if status['bundle_sha256'] != digest:
                raise ValueError('operation digest drift')
            if status['phase'] in TERMINAL:
                # Independent SSH after recovery is required before marking it accepted.
                addresses = spec['addresses'] if status['phase'] == 'committed' else spec['original_sources']
                if status['phase'] in ('committed', 'rolled_back'):
                    for family, address in zip((4, 6), addresses):
                        observed = remote(spec, directory, family, address, 'status')
                        if observed != status:
                            raise ValueError('independent terminal state mismatch')
                        dashboard = dashboard_https(spec, directory, address)
                        save(directory/('terminal-dashboard-'+str(family)+'.json'), dashboard)
                save(directory/'result.json', status)
                return status
            if status['phase'] == 'awaiting_confirmation' and not submitted:
                observations = []
                for family, address in zip((4, 6), spec['addresses']):
                    observation = remote(spec, directory, family, address, 'observe')
                    if set(observation.get('checks', {})) != {'address4', 'address6', 'routes', 'dns', 'dad', 'service_continuity'} or any(value is not True for value in observation['checks'].values()):
                        raise ValueError('independent network acceptance not converged')
                    observation.update(family=family, dashboard=dashboard_https(spec, directory, address))
                    observations.append(observation)
                proof = {'bundle_sha256': digest, 'challenge': status['challenge'], 'observations': observations}
                save(directory/'independent-confirmation.json', proof)
                submitted = True  # Ambiguous confirmation delivery is never replayed.
                remote(spec, directory, 4, spec['addresses'][0], 'confirm', proof)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            save(directory/'controller-error.json', {'type': type(error).__name__, 'epoch': time.time()})
        time.sleep(2)
    result = {'phase': 'recovery_held', 'reason': 'independent terminal acceptance unavailable', 'bundle_sha256': digest}
    save(directory/'result.json', result)
    return result


def accepted_capture(directory):
    spec_raw = (directory/'spec.json').read_bytes()
    capture_raw = (directory/'stdout.txt').read_bytes()
    spec = json.loads(spec_raw); capture = json.loads(capture_raw)
    receipt = json.loads((directory/'result.json').read_bytes())
    raw = (directory/'inspection.tar').read_bytes(); digest = sha(raw)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        if archive.extractfile('spec.json').read() != spec_raw:
            raise ValueError('archived baseline spec mismatch')
    if (receipt.get('returncode') != 0 or not receipt.get('capture_complete')
            or receipt.get('bundle_sha256') != digest or not capture.get('capture_complete')
            or capture.get('operation_id') != spec['operation_id'] or capture['spec_sha256'] != sha(spec_raw)):
        raise ValueError('accepted inspection provenance required')
    return spec, capture, digest, sha(capture_raw)


def seal(args):
    source_spec, capture, baseline_digest, _ = accepted_capture(args.baseline)
    profile_spec, profile_capture, profile_digest, profile_capture_digest = accepted_capture(args.profile_baseline)
    if (source_spec['baseline_bundle_sha256'] != profile_digest
            or source_spec['baseline_capture_sha256'] != profile_capture_digest
            or source_spec['boot_id'] != profile_spec['boot_id']
            or not profile_capture.get('persisted') or not profile_capture.get('running_network_unchanged')
            or not profile_capture['after']['identity_file_metadata']):
        raise ValueError('accepted profile-save/readiness continuity required')
    settings = json.loads((ROOT/'static-settings.json').read_bytes())
    dashboard_raw = (args.dashboard_baseline/'deployment.tar').read_bytes()
    dashboard_digest = sha(dashboard_raw)
    if dashboard_digest != '23aafda870c8cf1dc9863c48c5402ed8aa8306a06838c5d081f40760e0800941':
        raise ValueError('accepted Apache archive required')
    dashboard_result_raw = (args.dashboard_baseline/'result.json').read_bytes()
    dashboard_result = json.loads(dashboard_result_raw)
    dashboard_after_raw = (args.dashboard_baseline/'after.json').read_bytes()
    dashboard_after = json.loads(dashboard_after_raw)
    if (not dashboard_result.get('accepted') or not dashboard_result.get('https_verified')
            or dashboard_result['state'].get('phase') != 'committed'
            or dashboard_result['state'].get('sha256') != dashboard_digest
            or not dashboard_after.get('passed')):
        raise ValueError('accepted dual-stack HTTPS baseline required')
    with tarfile.open(fileobj=io.BytesIO(dashboard_raw), mode='r:') as dashboard_archive:
        trust = dashboard_archive.extractfile('ca.pem').read()
    now = int(time.time())
    spec = {'schema': 2, 'operation_id': args.operation_id, 'prepared_epoch': now,
        'expires_epoch': now+86400, 'hostname': source_spec['hostname'],
        'boot_id': source_spec['boot_id'], 'host_key_alias': source_spec['host_key_alias'],
        'user': source_spec['user'], 'interface': settings['interface'], 'uuid': settings['original_uuid'],
        'nm_version': capture['nm_version'].strip(), 'profile': capture['profile']['path'],
        'profile_sha256': profile_capture['persistent_file']['sha256'],
        'profile_metadata': {k: v for k, v in profile_capture['persistent_file'].items() if k != 'changed_during_read'},
        'identity_file_metadata': profile_capture['after']['identity_file_metadata'],
        'original_selected': {k: '' if v == '--' else v for k, v in capture['settings'].items()},
        'mac': capture['addresses'][0]['address'], 'checkpoint_seconds': settings['checkpoint_seconds'],
        'manager': dict(line.split('=', 1) for line in capture['manager_before'].splitlines()),
        'settings': settings['settings'], 'addresses': ['10.1.3.83', 'fd36:5aa8:6971:1::83'],
        'original_sources': [capture['node_route4'][0]['prefsrc'], capture['node_route6'][0]['prefsrc']],
        'ntp_addresses': NTP_ADDRESSES, 'gateway4': '10.1.0.1',
        'dns': ['10.1.0.55', 'fd36:5aa8:6971:1::55'], 'search': 'local.theama.co',
        'resolver_name': NTP_NAME,
        'dashboard_paths': ['/', '/static/style-new.css', '/munin-cgi/munin-cgi-graph/J1-SVMF/J1-SVMF/apache_accesses-day.png'],
        'dashboard_host': 'munin.local.theama.co',
        'dashboard_leaf_sha256': dashboard_after['rows'][0]['leaf_sha256'],
        'dashboard_baseline_sha256': dashboard_digest,
        'dashboard_result_sha256': sha(dashboard_result_raw), 'dashboard_after_sha256': sha(dashboard_after_raw),
        'apprise_port': 8000, 'mailrise_port': 8025,
        'units': ['NetworkManager.service', 'apache2.service', 'cron.service', 'ssh.service', 'munin-node.service'],
        'baseline_sha256': baseline_digest, 'profile_baseline_sha256': profile_digest}
    files = {name: (ROOT/name).read_bytes() for name in ('deploy.py', 'guard.py', 'static-settings.json')}
    files['tls_probe.py'] = (ROOT/'qualify_dashboard.py').read_bytes()
    files['ca.pem'] = trust
    files['known_hosts'] = (args.baseline/'known_hosts').read_bytes()
    if len(dashboard_after['rows']) != 6:
        raise ValueError('exact accepted six-response baseline required')
    for address in spec['original_sources']:
        valid_dashboard(spec, address, [row for row in dashboard_after['rows'] if row.get('address') == address])
    spec['members'] = {name: sha(raw) for name, raw in files.items()}
    files['spec.json'] = encoded(spec)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as output:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600
            output.addfile(info, io.BytesIO(raw))
    raw = archive.getvalue(); digest = sha(raw)
    unpack(raw, digest)
    os.umask(0o077); args.output.mkdir(mode=0o700)
    for name, data in files.items():
        write_new(args.output/name, data)
    write_new(args.output/'deployment.tar', raw)
    save(args.output/'sealing.json', {'sha256': digest, 'target_contact': False, 'expires_epoch': spec['expires_epoch']})
    return {'sha256': digest, 'target_contact': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('seal')
    prepare.add_argument('--baseline', type=Path, required=True)
    prepare.add_argument('--profile-baseline', type=Path, required=True)
    prepare.add_argument('--dashboard-baseline', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--operation-id', required=True)
    for name in ('execute', 'inspect'):
        item = sub.add_parser(name); item.add_argument('--directory', type=Path, required=True); item.add_argument('--sha256', required=True)
    for name in ('worker', 'status', 'readback', 'observe', 'confirm'):
        item = sub.add_parser(name); item.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.action == 'seal':
        result = seal(args)
    elif args.action in ('execute', 'inspect'):
        result = execute(args.directory.absolute(), args.sha256, args.action == 'inspect')
    else:
        if os.geteuid() != 0 or args.directory.resolve() != ROOT or ROOT.parent != STATE:
            raise ValueError('root and exact staged operation required')
        private(ROOT, True)
        if args.action == 'worker':
            worker(ROOT); return
        result = action(ROOT, args.action, json.load(sys.stdin) if args.action == 'confirm' else None)
    print(json.dumps(result))
    if args.action == 'execute' and result.get('phase') != 'committed':
        raise SystemExit(2)


if __name__ == '__main__':
    main()
