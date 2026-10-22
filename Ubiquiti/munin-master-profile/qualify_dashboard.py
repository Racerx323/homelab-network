"""Seal a single-use Apache/TLS diagnostic; no installation or configuration changes."""
import argparse
import hashlib
from html.parser import HTMLParser
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import tarfile
import time
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parent
HOST = 'munin.local.theama.co'
ADDRESSES = ['10.1.3.83', 'fd36:5aa8:6971:1:2cf5:3096:c5f:3283']
MEMBERS = {'qualify_dashboard.py', 'inspect_apache.py', 'test_qualify_dashboard.py',
           'spec.json', 'known_hosts', 'ca.pem', 'candidate.conf'}
BODY_LIMIT = 1048576


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


class Links(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.page = page
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag not in ('a', 'link', 'img'):
            return
        for key, value in attrs:
            if key not in ('href', 'src') or not value or len(value) > 256:
                continue
            parts = urlsplit(urljoin('https://'+HOST+self.page, value))
            if (parts.scheme != 'https' or parts.netloc != HOST or parts.query or parts.fragment
                    or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,240}', parts.path)
                    or any(x in ('.', '..') for x in parts.path.split('/'))):
                continue
            path = parts.path
            kind = 'page' if path.endswith('.html') else 'graph' if path.endswith('-day.png') else 'asset' if path.endswith('.css') and path.startswith(('/static/', '/munin/static/')) else None
            if kind and len(self.links) < 128 and (kind, path) not in self.links:
                self.links.append((kind, path))


class LiteralHTTPS(http.client.HTTPSConnection):
    def __init__(self, address, context):
        super().__init__(HOST, 443, timeout=5, context=context)
        self.address = address

    def connect(self):
        family = socket.AF_INET if ipaddress.ip_address(self.address).version == 4 else socket.AF_INET6
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(5)
        try:
            raw.connect((self.address, 443))
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def request(address, path, context):
    client = LiteralHTTPS(address, context)
    result = {'address': address, 'path': path, 'tls_verified': False}
    def deadline(_signum, _frame):
        raise TimeoutError('request deadline')
    old_handler = signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, 12)
    try:
        client.connect()
        result.update(tls_verified=True, tls_version=client.sock.version(),
                      source_address=client.sock.getsockname()[0],
                      leaf_sha256=sha(client.sock.getpeercert(binary_form=True)),
                      certificate=client.sock.getpeercert())
        client.request('GET', path, headers={'Host': HOST, 'Connection': 'close', 'Accept-Encoding': 'identity'})
        response = client.getresponse()
        body = response.read(BODY_LIMIT+1)
        content_type = (response.getheader('Content-Type') or '').split(';', 1)[0].strip().lower()
        result.update(status=response.status, content_type=content_type,
                      sampled_body_bytes=len(body), oversized=len(body) > BODY_LIMIT,
                      body_sha256=sha(body), png_signature=body.startswith(b'\x89PNG\r\n\x1a\n'),
                      location_sha256=sha((response.getheader('Location') or '').encode()))
        result['response_ok'] = response.status == 200 and 0 < len(body) <= BODY_LIMIT
        links = Links(path)
        if result['response_ok'] and content_type == 'text/html':
            links.feed(body.decode('utf-8', 'replace'))
        return result, links.links
    except Exception as error:
        result['error_type'] = type(error).__name__
        if isinstance(error, ssl.SSLCertVerificationError):
            result['verify_code'] = error.verify_code
        return result, []
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        client.close()


def probe_family(address, context):
    observations, found, visited = [], [], set()
    def visit(path):
        visited.add(path)
        row, links = request(address, path, context)
        observations.append(row)
        found.extend(link for link in links if link not in found)
    visit('/')
    # A failed verified handshake cannot be bypassed or retried at another path.
    if not observations[0]['tls_verified']:
        return {'address': address, 'observations': observations, 'page_asset_graph_accepted': False}
    visit('/munin/')
    for _ in range(3):
        pages = [path for kind, path in found if kind == 'page' and path not in visited]
        if not pages or any(kind == 'graph' for kind, _ in found):
            break
        visit(pages[0])
    for category in ('asset', 'graph'):
        candidates = [path for kind, path in found if kind == category and path not in visited]
        if candidates:
            visit(candidates[0])
    accepted = (any(r.get('response_ok') and r.get('content_type') == 'text/html' for r in observations)
                and any(r.get('response_ok') and r.get('content_type') == 'text/css' for r in observations)
                and any(r.get('response_ok') and r.get('content_type') == 'image/png' and r.get('png_signature') for r in observations))
    return {'address': address, 'observations': observations, 'page_asset_graph_accepted': accepted,
            'graph_freshness_accepted': False}


def unpack(raw, digest):
    if len(raw) > 1048576 or sha(raw) != digest:
        raise ValueError('archive hash/size')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        entries = archive.getmembers()
        if len(entries) != len(MEMBERS) or {e.name for e in entries} != MEMBERS or any(not e.isfile() or e.size > 524288 for e in entries):
            raise ValueError('closed regular member set')
        files = {e.name: archive.extractfile(e).read() for e in entries}
    spec = json.loads(files['spec.json'])
    if spec['members'] != {name: sha(data) for name, data in files.items() if name != 'spec.json'}:
        raise ValueError('member pins')
    if (spec['operation_id'] != 'svmf-apache-qualification-20261020-v1'
            or spec['addresses'] != ADDRESSES or spec['hostname'] != HOST
            or not spec['prepared_epoch'] <= time.time() < spec['expires_epoch']
            or spec['expires_epoch']-spec['prepared_epoch'] != 86400):
        raise ValueError('scope/expiry')
    return spec, files


def seal(baseline, candidate, output):
    old = (baseline/'deployment.tar').read_bytes()
    old_digest = json.loads((baseline/'sealing.json').read_bytes())['sha256']
    if sha(old) != old_digest:
        raise ValueError('baseline integrity')
    with tarfile.open(fileobj=io.BytesIO(old), mode='r:') as archive:
        old_spec = json.loads(archive.extractfile('spec.json').read())
        known_hosts = archive.extractfile('known_hosts').read()
    if old_spec['original_sources'] != ADDRESSES or old_spec['host_key_alias'] != 'svmf.local.theama.co':
        raise ValueError('baseline identity')
    files = {name: (ROOT/name).read_bytes() for name in ('qualify_dashboard.py', 'inspect_apache.py', 'test_qualify_dashboard.py')}
    files.update({'known_hosts': known_hosts, 'ca.pem': Path('/etc/ssl/certs/ca-certificates.crt').read_bytes(),
                  'candidate.conf': candidate.read_bytes()})
    context = ssl.create_default_context(cadata=files['ca.pem'].decode('ascii'))
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError('verified trust required')
    now = int(time.time())
    spec = {'operation_id': 'svmf-apache-qualification-20261020-v1', 'prepared_epoch': now,
            'expires_epoch': now+86400, 'addresses': ADDRESSES, 'hostname': HOST,
            'baseline_sha256': old_digest, 'members': {n: sha(d) for n, d in files.items()}}
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
    if files['qualify_dashboard.py'] != Path(__file__).read_bytes():
        raise ValueError('frozen runner required')
    for name in ('known_hosts',):
        if (directory/name).read_bytes() != files[name]:
            raise ValueError('frozen transport input required')
    context = ssl.create_default_context(cadata=files['ca.pem'].decode('ascii'))
    write(directory/'execution.json', encoded({'sha256': digest, 'epoch': int(time.time())}))
    options = ['BatchMode=yes', 'StrictHostKeyChecking=yes', 'HostKeyAlgorithms=ssh-ed25519',
               'UpdateHostKeys=no', 'ProxyCommand=none', 'ProxyJump=none', 'ControlMaster=no',
               'ControlPath=none', 'ControlPersist=no', 'PermitLocalCommand=no', 'ClearAllForwardings=yes',
               'ForwardAgent=no', 'ForwardX11=no', 'GlobalKnownHostsFile=/dev/null',
               'UserKnownHostsFile='+str(directory/'known_hosts'), 'HostKeyAlias=svmf.local.theama.co',
               'ConnectTimeout=5', 'ServerAliveInterval=5', 'ServerAliveCountMax=1']
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-4',
            *[item for option in options for item in ('-o', option)], 'pi@10.1.3.83',
            'cd / && sudo -n /usr/bin/python3 -I -B -']
    result = {'operation_id': spec['operation_id'], 'sha256': digest, 'configuration_mutation': False}
    try:
        p = subprocess.run(argv, input=files['inspect_apache.py'], capture_output=True, timeout=120)
        result['ssh'] = {'returncode': p.returncode, 'stderr_sha256': sha(p.stderr)}
        if len(p.stdout)+len(p.stderr) > 1048576 or p.returncode != 0:
            raise ValueError('remote transport/bound')
        remote = json.loads(p.stdout)
        candidate_hash = sha(files['candidate.conf'])
        remote['local_candidate_sha256'] = candidate_hash
        remote['candidate_matching_loaded_paths'] = [row['path'] for row in remote.get('configs', []) if row.get('sha256') == candidate_hash]
        result['apache'] = remote
    except Exception as error:
        result['ssh_error_type'] = type(error).__name__
    # Web requests occur even if SSH diagnosis fails, but never after archive validation fails.
    result['families'] = [probe_family(address, context) for address in spec['addresses']]
    result['network_change_accepted'] = False
    result['limitations'] = ['Requests may cause normal access logs and CGI graph-cache writes.',
                            'One sampled CSS/PNG is not full dashboard, freshness or every management-client acceptance.']
    write(directory/'result.json', encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('seal')
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('execute')
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--sha256', required=True)
    args = parser.parse_args()
    if args.action == 'seal':
        result = seal(args.baseline, args.candidate, args.output)
    else:
        result = execute(args.directory, args.sha256)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
