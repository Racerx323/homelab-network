"""Seal and execute a bounded HTTP metadata diagnostic; no SSH or configuration writes."""
import argparse
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import tarfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parent
MEMBERS = {'probe_dashboard.py', 'spec.json'}


def encoded(value):
    return (json.dumps(value, sort_keys=True)+'\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def location(raw):
    if not raw:
        return None
    parts = urllib.parse.urlsplit(raw)
    return {'sha256': sha(raw.encode()), 'scheme': parts.scheme, 'hostname': parts.hostname,
            'port': parts.port, 'path': parts.path if parts.path in ('/', '/munin/', '/munin') else 'other',
            'path_sha256': sha(parts.path.encode()), 'query_present': bool(parts.query)}


def probe(spec, address):
    client = http.client.HTTPConnection(address, spec['port'], timeout=3)
    try:
        client.request('GET', spec['path'], headers={'Host': spec['host_header'], 'Connection': 'close'})
        response = client.getresponse()
        body = response.read(65537)
        return {'address': address, 'status': response.status, 'sampled_body_bytes': len(body),
                'body_empty': not body, 'body_exceeds_gate_limit': len(body) > 65536,
                'location': location(response.getheader('Location')),
                'content_type': (response.getheader('Content-Type') or '')[:128],
                'authentication_scheme': (response.getheader('WWW-Authenticate') or '').split(' ', 1)[0][:32],
                'deployment_http_gate_passes': response.status == 200 and 0 < len(body) <= 65536}
    except Exception as error:
        return {'address': address, 'error_type': type(error).__name__, 'deployment_http_gate_passes': False}
    finally:
        client.close()


def unpack(raw, digest):
    if len(raw) > 262144 or sha(raw) != digest:
        raise ValueError('bundle integrity/size')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        entries = archive.getmembers()
        if len(entries) != 2 or {x.name for x in entries} != MEMBERS or any(not x.isfile() or x.size > 131072 for x in entries):
            raise ValueError('closed regular member set')
        files = {x.name: archive.extractfile(x).read() for x in entries}
    spec = json.loads(files['spec.json'])
    if spec['source_sha256'] != sha(files['probe_dashboard.py']):
        raise ValueError('source integrity')
    if not spec['prepared_epoch'] <= time.time() < spec['expires_epoch'] or spec['expires_epoch']-spec['prepared_epoch'] != 86400:
        raise ValueError('review expiry')
    if (not re.fullmatch(r'svmf-dashboard-[a-z0-9-]{1,48}', spec['operation_id'])
            or spec['port'] != 80 or spec['path'] != '/munin/' or spec['host_header'] != 'munin.local.theama.co'
            or len(spec['addresses']) != 2
            or [ipaddress.ip_address(a).version for a in spec['addresses']] != [4, 6]):
        raise ValueError('bounded endpoint scope')
    return spec, files


def seal(baseline, output, operation_id):
    # This consumes immutable approved deployment data, never executable sources.
    sealing = json.loads((baseline/'sealing.json').read_bytes())
    raw = (baseline/'deployment.tar').read_bytes()
    if sha(raw) != sealing['sha256']:
        raise ValueError('deployment baseline integrity')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        original = json.loads(archive.extractfile('spec.json').read())
    now = int(time.time())
    source = (ROOT/'probe_dashboard.py').read_bytes()
    spec = {'schema': 1, 'operation_id': operation_id, 'prepared_epoch': now, 'expires_epoch': now+86400,
            'baseline_archive_sha256': sealing['sha256'], 'addresses': original['original_sources'],
            'port': 80, 'path': '/munin/', 'host_header': 'munin.local.theama.co', 'source_sha256': sha(source)}
    files = {'probe_dashboard.py': source, 'spec.json': encoded(spec)}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name); entry.size = len(data); entry.mode = 0o600
            archive.addfile(entry, io.BytesIO(data))
    raw = buffer.getvalue(); digest = sha(raw); unpack(raw, digest)
    os.umask(0o077); output.mkdir(mode=0o700)
    for name, data in files.items(): write(output/name, data)
    write(output/'inspection.tar', raw)
    write(output/'sealing.json', encoded({'sha256': digest, 'expires_epoch': spec['expires_epoch'], 'target_contact': False}))
    return {'sha256': digest, 'target_contact': False}


def execute(directory, digest):
    spec, files = unpack((directory/'inspection.tar').read_bytes(), digest)
    if files['probe_dashboard.py'] != Path(__file__).read_bytes():
        raise ValueError('use frozen reviewed source')
    write(directory/'execution.json', encoded({'sha256': digest, 'epoch': int(time.time())}))
    # Exactly one GET per literal address, no redirect following, auth or retries.
    result = {'operation_id': spec['operation_id'], 'sha256': digest, 'target_contact': True,
              'target_configuration_mutation': False, 'observations': [probe(spec, a) for a in spec['addresses']]}
    write(directory/'result.json', encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('seal'); p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True); p.add_argument('--operation-id', required=True)
    p = sub.add_parser('execute'); p.add_argument('--directory', type=Path, required=True); p.add_argument('--sha256', required=True)
    args = parser.parse_args()
    result = seal(args.baseline, args.output, args.operation_id) if args.action == 'seal' else execute(args.directory, args.sha256)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
