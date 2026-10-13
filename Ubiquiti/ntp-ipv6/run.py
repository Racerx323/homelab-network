#!/usr/bin/env python3
"""Prepare offline or execute one hash-approved IPv6 NTP permit transaction."""
import argparse
import base64
import fcntl
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import types
import uuid

HERE = Path(__file__).resolve().parent


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private(path, limit=64 * 1024 ** 2):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and
            info.st_uid == os.getuid() and info.st_size <= limit, 'private regular file required')
    return path.read_bytes()


def write(path, value):
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def module(raw):
    value = types.ModuleType('sealed_policy')
    exec(compile(raw, 'sealed_policy.py', 'exec'), value.__dict__)
    return value


class API:
    def __init__(self, spec, baseline):
        self.spec, self.baseline = spec, baseline
        self.base = '/proxy/network/integration/v1/sites/' + spec['site_id']
        self.key = None
        self.count = self.total = 0
        self.context = ssl.create_default_context()
        self.deadline = time.monotonic() + 600

    def authenticate(self):
        s = self.spec
        resolved = {x[4][0] for x in socket.getaddrinfo(s['controller'], 443,
                                                     socket.AF_INET, socket.SOCK_STREAM)}
        require(resolved == {s['controller_ipv4']}, 'controller DNS drift')
        self.request('GET', '/', precheck=True)
        result = subprocess.run(['doppler', 'secrets', 'get', 'AUDIT_LOCAL', '--project',
                                 'homelab-dev', '--config', 'prd_unifi', '--plain',
                                 '--no-check-version'], capture_output=True, timeout=30)
        require(result.returncode == 0, 'credential retrieval failed')
        self.key = result.stdout.decode().strip()
        require(self.key and '\n' not in self.key and '\r' not in self.key, 'credential shape')

    def request(self, method, path, payload=None, precheck=False):
        self.count += 1
        require(self.count <= 240 and time.monotonic() < self.deadline, 'API request/deadline bound')
        require((precheck and method == 'GET' and path == '/') or
                path == '/proxy/network/integration/v1/info' or path.startswith(self.base + '/'),
                'local API scope')
        require(method in ('GET', 'POST', 'PUT', 'DELETE'), 'method scope')
        connection = http.client.HTTPSConnection(self.spec['controller'], timeout=10,
                                                context=self.context)
        raw = socket.create_connection((self.spec['controller_ipv4'], 443), timeout=10)
        try:
            connection.sock = self.context.wrap_socket(raw, server_hostname=self.spec['controller'])
            headers = {'Accept': 'application/json'}
            if not precheck:
                require(bool(self.key), 'authentication required')
                headers['X-API-KEY'] = self.key
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            connection.request(method, path, body=None if payload is None else encoded(payload),
                               headers=headers)
            response = connection.getresponse()
            data = response.read(2 * 1024 ** 2 + 1)
            self.total += len(data)
            require(len(data) <= 2 * 1024 ** 2 and self.total <= 64 * 1024 ** 2,
                    'API response bound')
            expected = (200, 301, 302, 303, 307, 308) if precheck else ((201,) if method == 'POST' else (200,))
            require(response.status in expected, 'API status ' + str(response.status))
            if precheck or method == 'DELETE':
                return None
            require(self.key.encode() not in data, 'credential reflected by API')
            return json.loads(data)
        finally:
            connection.close()
            raw.close()

    def pages(self, path):
        rows = []
        for offset in range(0, 400, 100):
            value = self.request('GET', path + '?limit=100&offset=' + str(offset))
            require(value['offset'] == offset and len(value['data']) <= 100, 'pagination shape')
            rows.extend(value['data'])
            require(len(rows) <= value['totalCount'] <= 400, 'pagination bound')
            if len(rows) == value['totalCount']:
                require(len({x['id'] for x in rows}) == len(rows), 'duplicate API object ID')
                require(all(str(uuid.UUID(x['id'])) == x['id'] for x in rows), 'canonical API object ID')
                return sorted(rows, key=lambda x: x['id'])
            require(bool(value['data']), 'pagination stalled')
        raise ValueError('pagination incomplete')

    def snapshot(self):
        return {'version': self.request('GET', '/proxy/network/integration/v1/info'),
                'policies': self.pages(self.base + '/firewall/policies'),
                'networks': self.pages(self.base + '/networks'),
                'zones': self.pages(self.base + '/firewall/zones'),
                'order': self.request('GET', self.base + '/firewall/policies/ordering?' + self.spec['order_query']),
                'reverse_order': self.request('GET', self.base + '/firewall/policies/ordering?' + self.spec['reverse_query']),
                'lists': {identifier: self.request('GET', self.base + '/traffic-matching-lists/' + identifier)
                          for identifier in self.baseline['lists']}}

    def create(self, policy):
        return self.request('POST', self.base + '/firewall/policies', policy)

    def order(self, order):
        return self.request('PUT', self.base + '/firewall/policies/ordering?' + self.spec['order_query'], order)

    def update(self, identifier, policy):
        require(str(uuid.UUID(identifier)) == identifier, 'policy UUID')
        return self.request('PUT', self.base + '/firewall/policies/' + identifier, policy)

    def delete(self, identifier):
        require(str(uuid.UUID(identifier)) == identifier, 'policy UUID')
        return self.request('DELETE', self.base + '/firewall/policies/' + identifier)


def probe_result(directory, spec, want_success):
    accepted = json.loads(private(directory / 'inspection-acceptance.json'))
    require(accepted['node']['state'] == 'diagnostics_captured' and
            accepted['controller']['state'] == 'captured', 'diagnostic not accepted')
    report = json.loads(private(directory / 'readback-1-0-result.json'))['result']
    evidence = report['evidence']
    decoded = {}
    for name, entry in evidence.items():
        raw = base64.b64decode(entry['base64'], validate=True)
        require(sha(raw) == entry['sha256'], 'embedded evidence digest')
        decoded[name] = raw
    interfaces = json.loads(decoded['addresses.stdout'])
    nic = [x for x in interfaces if x['ifname'] == 'eth0']
    require(len(nic) == 1 and nic[0]['address'] == spec['mac'], 'host Ethernet identity drift')
    routes = json.loads(decoded['routes.json'])
    require(len(routes) == 6 and all(len(x['route']) == 1 and x['route'][0]['dev'] == 'eth0'
                                   for x in routes), 'public egress interface drift')
    rows = []
    for context in ('root', 'ntp'):
        rows.extend(json.loads(decoded[context + '-probes.stdout']))
    require(len(rows) == 12 and all('address' in x for x in rows), 'probe coverage')
    if want_success:
        require(all(x['connected'] for x in rows), 'dual-stack TCP acceptance failed')
    require(json.loads(private(directory / 'cleanup-0-result.json'))['result']['phase'] == 'cleaned',
            'diagnostic cleanup missing')
    return rows


def capture(directory, spec, label, checkpoint):
    child = spec['children'][label]
    folder = directory / label
    archive = folder / 'cutover-inspection.tar'
    require(sha(private(archive)) == child['sha256'], 'child archive changed')
    runner = spec['diagnostic_runner']
    for mode in ('unifi', 'start', 'readback', 'cleanup'):
        command = ['/usr/bin/python3', '-I', '-B', runner, 'execute', '--bundle', str(archive),
                   '--sha256', child['sha256'], '--mode', mode]
        checkpoint(label + '-' + mode + '-intent.json', {'argv': command})
        log = folder / ('parent-' + mode + '.log')
        with log.open('xb') as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=420,
                                    cwd=spec['ntp_repo'], env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        require(result.returncode == 0, 'child ' + label + '/' + mode + ' failed; never replay capture')
        if mode == 'unifi':
            require(json.loads(private(folder / 'unifi-receipt.json'))['state'] == 'captured',
                    'controller capture held')
    return probe_result(folder, spec, label == 'after')


def unpack(path, digest):
    raw = private(path)
    require(sha(raw) == digest, 'approved archive digest mismatch')
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        members = archive.getmembers()
        require(all(x.isfile() and '/' not in x.name and x.size <= 16 * 1024 ** 2 for x in members),
                'archive member shape')
        require(len({x.name for x in members}) == len(members), 'duplicate archive member')
        files = {x.name: archive.extractfile(x).read() for x in members}
    manifest = json.loads(files.pop('manifest.json'))
    require({n: sha(v) for n, v in files.items()} == manifest, 'archive manifest')
    require(files['run.py'] == Path(__file__).read_bytes(), 'runner revision mismatch')
    return files


def execute(args):
    directory = args.bundle.resolve().parent
    info = directory.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private operation directory')
    files = unpack(args.bundle, args.sha256)
    spec = json.loads(files['spec.json'])
    baseline = json.loads(files['baseline.json'])
    policy = module(files['policy.py'])
    for name, digest in spec['execution_inputs'].items():
        require(sha(Path(name).read_bytes()) == digest, 'diagnostic executable changed')
    lock = os.open(directory / 'execution.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    attempt = directory / args.mode
    attempt.mkdir(mode=0o700)  # Exclusive registration: no replay after transport loss.
    write(attempt / 'authorization.json', {'sha256': args.sha256, 'epoch': int(time.time())})

    def checkpoint(name, value):
        write(attempt / name, value)

    api = API(spec, baseline)
    mutated = False
    try:
        if args.mode == 'apply':
            require(spec['prepared_epoch'] - 300 <= time.time() < spec['start_before_epoch'], 'execution window')
            capture(directory, spec, 'before', checkpoint)
            before = json.loads(private(directory / 'before' / 'unifi-report.json'))
            require(policy.from_report(before, spec) == baseline, 'preflight controller snapshot drift')
            api.authenticate()
            mutated = True  # Recovery discovers exact owned objects even if POST reply is lost.
            policy.apply(api, baseline, spec, checkpoint)
            capture(directory, spec, 'after', checkpoint)
            policy.accepted(api.snapshot(), baseline, spec)
            checkpoint('accepted.json', {'state': 'policy_and_tcp_accepted', 'time_service_accepted': False})
        else:
            require((directory / 'apply' / 'authorization.json').exists(), 'registered apply required')
            require(not (directory / 'apply' / 'accepted.json').exists(),
                    'accepted operation needs new rollback approval')
            api.authenticate()
            policy.recover(api, baseline, spec, checkpoint)
            # Recovery probes run once only; preserve an earlier interrupted capture.
            if not (directory / 'recovery' / 'unifi-execution.json').exists():
                capture(directory, spec, 'recovery', checkpoint)
        return {'state': 'accepted' if args.mode == 'apply' else 'recovered'}
    except Exception as error:
        checkpoint('failure.json', {'error_class': type(error).__name__,
                   'reason': str(error) if type(error) is ValueError else 'see recorded operation intents',
                   'mutation_may_have_started': mutated})
        if mutated:
            recovery = directory / 'automatic-recovery'
            recovery.mkdir(mode=0o700)
            try:
                fresh = API(spec, baseline)
                fresh.authenticate()
                policy.recover(fresh, baseline, spec, lambda n, v: write(recovery / n, v))
                capture(directory, spec, 'recovery', lambda n, v: write(recovery / n, v))
                return {'state': 'recovered_after_failure', 'time_service_accepted': False}
            except Exception as recovery_error:
                write(recovery / 'failure.json', {'error_class': type(recovery_error).__name__,
                      'reason': str(recovery_error) if type(recovery_error) is ValueError else 'see recovery intents'})
        return {'state': 'held', 'recovery_required': mutated or args.mode == 'recover'}
    finally:
        api.key = None
        os.close(lock)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--mode', choices=('apply', 'recover'), required=True)
    args = parser.parse_args()
    try:
        result = execute(args)
    except Exception as error:
        result = {'state': 'held', 'error_class': type(error).__name__}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['state'] in ('accepted', 'recovered', 'recovered_after_failure') else 1


if __name__ == '__main__':
    sys.exit(main())
