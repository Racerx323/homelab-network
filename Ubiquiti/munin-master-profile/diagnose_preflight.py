"""Seal a single read-only SSH capture of the consumed svmf v2 preflight failure."""
import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tarfile
import time

OPERATION = 'svmf-preflight-diagnostic-20261020-v1'
RESOLVER_OPERATION = 'svmf-resolver-diagnostic-20261020-v1'
RESOLVER_NAME = 'ntp1.local.theama.co'
FAILED_OPERATION = 'svmf-network-20261020-v2'
BASELINE = '20e8297328c270b3c623076479ae6feb35f5f855bfc3e49e44c531f99fb8de83'
BASELINE_SPEC_SHA = '055a61e6f302ab12925b72f3e33428b34cdd0db15bfcbc092a619270b3c606e5'
STAGE = Path('/var/lib/svmf-network')/FAILED_OPERATION
PROFILE = Path('/etc/NetworkManager/system-connections/Wired connection 1.nmconnection')
BOOT = '63bb54d2-d6ea-44fb-ac15-825f10475868'
UUID = '2cad90ef-210e-329a-bc55-9e23fa8160dd'
MEMBERS = {'diagnose_preflight.py', 'test_diagnose_preflight.py', 'known_hosts', 'baseline.json', 'spec.json'}


def encoded(value):
    return (json.dumps(value, sort_keys=True)+'\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def protected_read(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('protected ancestry required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_mode & 0o077 or before.st_size > 262144):
            raise ValueError('bounded root-private regular file required')
        raw = stream.read(262145)
        after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda info: tuple(getattr(info, k) for k in keys)
    if len(raw) > 262144 or identity(before) != identity(after) or identity(after) != identity(path.lstat()):
        raise ValueError('file changed during read')
    return raw, {'sha256': sha(raw), 'uid': after.st_uid, 'gid': after.st_gid,
                 'mode': stat.S_IMODE(after.st_mode), 'size': after.st_size,
                 'inode': after.st_ino, 'device': after.st_dev, 'mtime_ns': after.st_mtime_ns}


def command(argv):
    row = subprocess.run(argv, capture_output=True, timeout=8,
                         env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if row.returncode or len(row.stdout)+len(row.stderr) > 65536:
        raise ValueError('selected read-only command failed')
    return row.stdout.decode()


def identity():
    if (os.geteuid() != 0 or socket.gethostname() != 'J1-SVMF'
            or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != BOOT
            or Path('/sys/class/net/eth0/address').read_text().strip() != '2c:cf:67:ee:53:bd'):
        raise ValueError('root/host/boot/interface identity drift')
    active = command(['/usr/bin/nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active'])
    if [line for line in active.splitlines() if line.endswith(':eth0')] != [UUID+':eth0']:
        raise ValueError('active UUID drift')
    return command(['/usr/bin/systemctl', 'show', 'NetworkManager.service',
                    '--property=MainPID,InvocationID,NRestarts,ActiveState,SubState'])


def collect():
    before = identity()
    raw, state_metadata = protected_read(STAGE/'state.json')
    state = json.loads(raw)
    if state.get('operation_id') != FAILED_OPERATION or state.get('bundle_sha256') != BASELINE:
        raise ValueError('retained operation identity mismatch')
    spec_raw, _ = protected_read(STAGE/'spec.json')
    spec = json.loads(spec_raw)
    if (sha(spec_raw) != BASELINE_SPEC_SHA or spec.get('operation_id') != FAILED_OPERATION
            or spec.get('profile') != str(PROFILE)):
        raise ValueError('retained specification identity mismatch')
    selected = {k: state[k] for k in ('phase', 'updated', 'phase_before_failure', 'error', 'recovery_error') if k in state}
    if any(isinstance(v, str) and (len(v) > 2048 or any(ord(c) < 32 for c in v)) for v in selected.values()):
        raise ValueError('failure field bound')
    _, metadata = protected_read(PROFILE)
    unit = command(['/usr/bin/systemctl', 'show', FAILED_OPERATION+'.service',
                    '--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,NRestarts'])
    after = identity()
    if before != after or protected_read(STAGE/'state.json')[0] != raw:
        raise ValueError('manager or retained state changed during capture')
    return {'capture_complete': True, 'target_mutation': False, 'state': selected,
            'state_metadata': state_metadata, 'spec_sha256': sha(spec_raw), 'profile_metadata': metadata,
            'profile_content_matches_baseline': metadata['sha256'] == spec['profile_sha256'],
            'profile_metadata_matches_baseline': all(metadata.get(k) == v for k, v in spec['profile_metadata'].items()),
            'manager': before, 'worker_unit': unit, 'network_configuration_accepted': False}


def resolver_command(argv, timeout=5):
    """Nonzero lookup status is diagnostic evidence, never a capture exception."""
    try:
        row = subprocess.run(argv, capture_output=True, timeout=timeout,
                             env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        result = {'argv': argv, 'returncode': row.returncode, 'stdout_bytes': len(row.stdout),
                  'stderr_bytes': len(row.stderr), 'stderr_sha256': sha(row.stderr)}
        if len(row.stdout)+len(row.stderr) > 65536:
            return dict(result, error='output_bound')
        return dict(result, stdout=row.stdout.decode('utf-8', 'replace'))
    except subprocess.TimeoutExpired:
        return {'argv': argv, 'error': 'timeout'}
    except OSError as error:
        return {'argv': argv, 'error': type(error).__name__}


def resolver_file(path):
    """Read only selected system resolver files, allowing known resolv.conf links."""
    allowed = {'/etc/nsswitch.conf', '/etc/hosts', '/etc/resolv.conf',
               '/run/NetworkManager/resolv.conf', '/run/resolvconf/resolv.conf',
               '/run/systemd/resolve/stub-resolv.conf', '/run/systemd/resolve/resolv.conf'}
    actual = path.resolve(strict=True)
    if str(actual) not in allowed or (path.name != 'resolv.conf' and actual != path):
        raise ValueError('resolver file outside scope')
    for parent in actual.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe resolver ancestry')
    fd = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_size > 65536:
            raise ValueError('unsafe resolver file')
        raw = stream.read(65537); after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    same = lambda info: tuple(getattr(info, k) for k in keys)
    if len(raw) > 65536 or same(before) != same(after) or same(after) != same(actual.lstat()) or path.resolve(strict=True) != actual:
        raise ValueError('resolver file drift')
    selected = []
    for line in raw.decode().splitlines():
        fields = line.split('#', 1)[0].split()
        if not fields:
            continue
        if ((path.name == 'nsswitch.conf' and fields[0] == 'hosts:')
                or (path.name == 'resolv.conf' and fields[0] in ('nameserver', 'search', 'domain', 'options'))
                or (path.name == 'hosts' and RESOLVER_NAME in fields[1:])):
            if len(line) > 2048 or len(selected) >= 64:
                raise ValueError('resolver projection bound')
            selected.append(' '.join(fields))
    return {'resolved_path': str(actual), 'sha256': sha(raw), 'selected_lines': selected}


def lookup_addresses(row):
    addresses = set()
    for line in row.get('stdout', '').splitlines():
        fields = line.split()
        if fields:
            try:
                addresses.add(str(ipaddress.ip_address(fields[0])))
            except ValueError:
                continue
    return sorted(addresses)


def collect_resolver():
    before = identity()
    result = {'lookup_name': RESOLVER_NAME, 'target_mutation': False,
              'network_configuration_accepted': False, 'files': {}, 'findings': []}
    for name in ('/etc/nsswitch.conf', '/etc/resolv.conf', '/etc/hosts'):
        try:
            result['files'][name] = resolver_file(Path(name))
        except Exception as error:
            result['files'][name] = {'error_type': type(error).__name__}
            result['findings'].append('selected resolver file unavailable: '+name)
    result['runtime_dns'] = resolver_command(['/usr/bin/nmcli', '-m', 'multiline', '-f',
        'IP4.DNS,IP4.DOMAIN,IP6.DNS,IP6.DOMAIN', 'device', 'show', 'eth0'])
    result['lookups'] = {}
    for family, expected in (('ahostsv4', '10.1.0.51'), ('ahostsv6', 'fd36:5aa8:6971:1::51')):
        row = resolver_command(['/usr/bin/getent', family, RESOLVER_NAME])
        row['addresses'] = lookup_addresses(row)
        row['expected_address_present'] = row.get('returncode') == 0 and expected in row['addresses']
        result['lookups'][family] = row
    # Optional fixed-endpoint DNS queries distinguish NSS from DNS evidence.
    dig = Path('/usr/bin/dig')
    if dig.is_file() and not dig.is_symlink() and dig.stat().st_uid == 0 and not dig.stat().st_mode & 0o022:
        result['direct_dns'] = [resolver_command(['/usr/bin/dig', '-r', '@'+server,
            RESOLVER_NAME+'.', kind, '+time=2', '+tries=1', '+ignore', '+nosearch',
            '+nocookie', '+noall', '+comments', '+answer', '+stats'], timeout=3)
            for server in ('10.1.0.55', 'fd36:5aa8:6971:1::55') for kind in ('A', 'AAAA')]
    else:
        result['findings'].append('protected /usr/bin/dig unavailable; no install or fallback')
    after = identity()
    if before != after:
        raise ValueError('manager identity changed during resolver capture')
    for name, previous in result['files'].items():
        if 'sha256' in previous and resolver_file(Path(name)) != previous:
            raise ValueError('resolver files changed during capture')
    result.update(manager=before, capture_complete=not any('error_type' in v for v in result['files'].values()))
    return result


def unpack(raw, digest):
    if sha(raw) != digest or len(raw) > 1048576:
        raise ValueError('archive hash/size')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        entries = archive.getmembers()
        if len(entries) != len(MEMBERS) or {e.name for e in entries} != MEMBERS or any(not e.isfile() or e.size > 262144 for e in entries):
            raise ValueError('closed regular member set')
        files = {e.name: archive.extractfile(e).read() for e in entries}
    spec = json.loads(files['spec.json'])
    kind = spec.get('kind', 'preflight')
    if (kind not in ('preflight', 'resolver')
            or spec['operation_id'] != (RESOLVER_OPERATION if kind == 'resolver' else OPERATION)
            or (kind == 'resolver' and spec.get('lookup_name') != RESOLVER_NAME)
            or spec['baseline_sha256'] != BASELINE
            or not spec['prepared_epoch'] <= time.time() < spec['expires_epoch']
            or spec['expires_epoch']-spec['prepared_epoch'] != 86400
            or spec['members'] != {n: sha(d) for n, d in files.items() if n != 'spec.json'}):
        raise ValueError('scope, expiry or member integrity')
    return files


def seal(baseline, output, resolver=False):
    approved_raw = (baseline/'deployment.tar').read_bytes()
    if sha(approved_raw) != BASELINE:
        raise ValueError('approved failed archive required')
    with tarfile.open(fileobj=io.BytesIO(approved_raw), mode='r:') as archive:
        known_hosts = archive.extractfile('known_hosts').read()
        if sha(archive.extractfile('spec.json').read()) != BASELINE_SPEC_SHA:
            raise ValueError('approved specification required')
    state = json.loads((baseline/'result.json').read_bytes())
    if state.get('phase') != 'preflight_failed' or state.get('bundle_sha256') != BASELINE:
        raise ValueError('failed preflight receipt required')
    root = Path(__file__).resolve().parent
    files = {n: (root/n).read_bytes() for n in ('diagnose_preflight.py', 'test_diagnose_preflight.py')}
    files.update({'known_hosts': known_hosts, 'baseline.json': encoded(state)})
    now = int(time.time())
    files['spec.json'] = encoded({'operation_id': RESOLVER_OPERATION if resolver else OPERATION,
        'kind': 'resolver' if resolver else 'preflight', 'lookup_name': RESOLVER_NAME if resolver else None,
        'baseline_sha256': BASELINE,
        'prepared_epoch': now, 'expires_epoch': now+86400, 'members': {n: sha(d) for n, d in files.items()}})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name); entry.size = len(data); entry.mode = 0o600
            archive.addfile(entry, io.BytesIO(data))
    raw = buffer.getvalue(); digest = sha(raw)
    unpack(raw, digest)
    os.umask(0o077); output.mkdir(mode=0o700)
    for name, data in files.items():
        write(output/name, data)
    write(output/'inspection.tar', raw)
    write(output/'sealing.json', encoded({'sha256': digest, 'expires_epoch': now+86400}))
    return {'sha256': digest, 'directory': str(output)}


def execute(directory, digest):
    os.umask(0o077)
    if directory.is_symlink() or directory.stat().st_uid != os.geteuid() or directory.stat().st_mode & 0o077:
        raise ValueError('private execution directory required')
    files = unpack((directory/'inspection.tar').read_bytes(), digest)
    resolver = json.loads(files['spec.json']).get('kind') == 'resolver'
    if files['diagnose_preflight.py'] != Path(__file__).read_bytes() or files['known_hosts'] != (directory/'known_hosts').read_bytes():
        raise ValueError('frozen execution inputs required')
    options = ['BatchMode=yes', 'StrictHostKeyChecking=yes', 'HostKeyAlgorithms=ssh-ed25519',
        'UpdateHostKeys=no', 'ProxyCommand=none', 'ProxyJump=none', 'ControlMaster=no',
        'ControlPath=none', 'ControlPersist=no', 'PermitLocalCommand=no', 'ClearAllForwardings=yes',
        'ForwardAgent=no', 'ForwardX11=no', 'GlobalKnownHostsFile=/dev/null',
        'UserKnownHostsFile='+str(directory/'known_hosts'), 'HostKeyAlias=svmf.local.theama.co',
        'ConnectTimeout=5', 'ServerAliveInterval=5', 'ServerAliveCountMax=1']
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-4',
        *[item for option in options for item in ('-o', option)], 'pi@10.1.3.83',
        'cd / && /usr/bin/sudo -n /usr/bin/python3 -I -B - '+('collect-resolver' if resolver else 'collect')]
    write(directory/'execution.json', encoded({'sha256': digest, 'epoch': time.time(), 'argv': argv}))
    try:
        row = subprocess.run(argv, input=files['diagnose_preflight.py'], capture_output=True, timeout=90 if resolver else 55)
    except subprocess.TimeoutExpired as error:
        write(directory/'transport.json', encoded({'timed_out': True}))
        raise ValueError('transport timed out; receipt consumed') from error
    write(directory/'stdout.txt', row.stdout[:262144]); write(directory/'stderr.txt', row.stderr[:65536])
    if row.returncode or len(row.stdout) > 262144 or len(row.stderr) > 65536:
        raise ValueError('transport failed; receipt consumed')
    result = json.loads(row.stdout)
    write(directory/'result.json', encoded(result))
    return result


def main():
    if sys.argv[1:] in (['collect'], ['collect-resolver']):
        try:
            print(json.dumps(collect_resolver() if sys.argv[1] == 'collect-resolver' else collect()))
        except Exception as error:
            print(json.dumps({'capture_complete': False, 'error_type': type(error).__name__}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('seal'); prepare.add_argument('--baseline', type=Path, required=True); prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--resolver', action='store_true')
    run = sub.add_parser('execute'); run.add_argument('--directory', type=Path, required=True); run.add_argument('--sha256', required=True)
    args = parser.parse_args()
    result = seal(args.baseline, args.output, args.resolver) if args.action == 'seal' else execute(args.directory.absolute(), args.sha256)
    print(json.dumps(result))
    if args.action == 'execute' and not result.get('capture_complete'):
        sys.exit(2)


if __name__ == '__main__':
    main()
