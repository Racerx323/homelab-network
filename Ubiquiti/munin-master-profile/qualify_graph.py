"""Seal single-use, verified HTTPS graph discovery beneath the observed master domain."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import tarfile
import time

ROOT = Path(__file__).resolve().parent
OPERATION = 'svmf-graph-qualification-20261020-v1'
BASELINE = '87ba990d3cdbc21321f8aabfec18ea0e5549eaf985af7c4a81318ae0cc1f8ed2'
ADDRESSES = ['10.1.3.83', 'fd36:5aa8:6971:1:2cf5:3096:c5f:3283']
PREFIX = '/J1-SVMF/'
SEED = PREFIX+'index.html'
MEMBERS = {'qualify_graph.py', 'qualify_dashboard.py', 'test_qualify_graph.py',
           'ca.pem', 'baseline.json', 'spec.json'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True)+'\n').encode()


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_helper():
    loader = importlib.util.spec_from_file_location('dashboard_transport', ROOT/'qualify_dashboard.py')
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    return module


def eligible(kind, path):
    if kind == 'page':
        return path.startswith(PREFIX) and path.endswith('.html')
    if kind == 'graph':
        return path.startswith((PREFIX, '/munin-cgi/munin-cgi-graph'+PREFIX)) and path.endswith('-day.png')
    return kind == 'asset' and path.startswith(('/static/', '/munin/static/')) and path.endswith('.css')


def discover(helper, address, context):
    frontier, visited, observations, discovered = [SEED], set(), [], []
    for _ in range(4):
        if not frontier:
            break
        path = frontier.pop(0)
        visited.add(path)
        row, links = helper.request(address, path, context)
        observations.append(row)
        if not row.get('tls_verified'):
            return {'address': address, 'observations': observations, 'eligible_links': discovered, 'accepted': False}
        safe = [link for link in links if eligible(*link)]
        discovered.extend(link for link in safe if link not in discovered)
        if any(kind == 'graph' for kind, _ in discovered):
            break
        # Descend this page's links before siblings; never leave the observed domain.
        children = [path for kind, path in safe if kind == 'page' and path not in visited]
        frontier = list(dict.fromkeys(children+[p for p in frontier if p not in visited]))
    for kind in ('asset', 'graph'):
        paths = [path for category, path in discovered if category == kind]
        if paths:
            row, _ = helper.request(address, paths[0], context)
            observations.append(row)
            if not row.get('tls_verified'):
                break
    accepted = (any(r.get('response_ok') and r.get('content_type') == 'text/html' for r in observations)
                and any(r.get('response_ok') and r.get('content_type') == 'text/css' for r in observations)
                and any(r.get('response_ok') and r.get('content_type') == 'image/png' and r.get('png_signature') for r in observations))
    return {'address': address, 'observations': observations, 'eligible_links': discovered,
            'accepted': accepted, 'graph_freshness_accepted': False}


def unpack(raw, digest):
    if len(raw) > 1048576 or sha(raw) != digest:
        raise ValueError('archive hash/size')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        entries = archive.getmembers()
        if len(entries) != len(MEMBERS) or {e.name for e in entries} != MEMBERS or any(not e.isfile() or e.size > 524288 for e in entries):
            raise ValueError('closed regular member set')
        files = {e.name: archive.extractfile(e).read() for e in entries}
    spec = json.loads(files['spec.json'])
    if spec['members'] != {n: sha(d) for n, d in files.items() if n != 'spec.json'}:
        raise ValueError('member pins')
    if (spec['operation_id'] != OPERATION or spec['baseline_sha256'] != BASELINE
            or spec['addresses'] != ADDRESSES or spec['seed'] != SEED
            or not spec['prepared_epoch'] <= time.time() < spec['expires_epoch']
            or spec['expires_epoch']-spec['prepared_epoch'] != 86400):
        raise ValueError('scope/expiry')
    return spec, files


def seal(baseline, output):
    raw = (baseline/'inspection.tar').read_bytes()
    if sha(raw) != BASELINE:
        raise ValueError('approved baseline integrity')
    observed_raw = (baseline/'result.json').read_bytes()
    observed = json.loads(observed_raw)
    if observed['sha256'] != BASELINE:
        raise ValueError('baseline capture identity')
    for address in ADDRESSES:
        families = [f for f in observed['families'] if f['address'] == address]
        if len(families) != 1 or not any(r['path'] == SEED and r.get('tls_verified') and r.get('status') == 200 for r in families[0]['observations']):
            raise ValueError('observed seed required')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        trust = archive.extractfile('ca.pem').read()
    # Prior evidence supplies public trust/provenance only; executable code comes from this repository.
    files = {n: (ROOT/n).read_bytes() for n in ('qualify_graph.py', 'qualify_dashboard.py', 'test_qualify_graph.py')}
    files['ca.pem'] = trust
    ssl.create_default_context(cadata=trust.decode('ascii'))
    files['baseline.json'] = encoded({'archive_sha256': BASELINE, 'result_sha256': sha(observed_raw),
                                      'seed': SEED, 'observed_addresses': ADDRESSES})
    now = int(time.time())
    spec = {'operation_id': OPERATION, 'baseline_sha256': BASELINE, 'addresses': ADDRESSES,
            'seed': SEED, 'prepared_epoch': now, 'expires_epoch': now+86400,
            'members': {n: sha(d) for n, d in files.items()}}
    files['spec.json'] = encoded(spec)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o600
            archive.addfile(entry, io.BytesIO(data))
    raw = buffer.getvalue()
    digest = sha(raw)
    unpack(raw, digest)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    for name, data in files.items():
        write(output/name, data)
    write(output/'inspection.tar', raw)
    write(output/'sealing.json', encoded({'sha256': digest, 'expires_epoch': now+86400, 'target_contact': False}))
    return {'sha256': digest, 'target_contact': False}


def execute(directory, digest):
    spec, files = unpack((directory/'inspection.tar').read_bytes(), digest)
    if Path(__file__).read_bytes() != files['qualify_graph.py'] or ROOT != directory.resolve():
        raise ValueError('use frozen runner directory')
    if (directory/'qualify_dashboard.py').read_bytes() != files['qualify_dashboard.py']:
        raise ValueError('frozen transport helper required')
    helper = load_helper()
    context = ssl.create_default_context(cadata=files['ca.pem'].decode('ascii'))
    write(directory/'execution.json', encoded({'sha256': digest, 'epoch': int(time.time())}))
    result = {'operation_id': spec['operation_id'], 'sha256': digest, 'configuration_mutation': False,
              'families': [discover(helper, address, context) for address in spec['addresses']],
              'network_change_accepted': False, 'graph_freshness_accepted': False}
    write(directory/'result.json', encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('seal')
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('execute')
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(seal(args.baseline, args.output) if args.action == 'seal' else execute(args.directory, args.sha256)))


if __name__ == '__main__':
    main()
