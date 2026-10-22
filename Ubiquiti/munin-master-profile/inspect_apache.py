"""Read-only Apache qualification payload, submitted on stdin through pinned SSH."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

HOST = 'J1-SVMF'
BOOT = '63bb54d2-d6ea-44fb-ac15-825f10475868'
PUBLIC_CERTS = ('/etc/ssl/local.theama.co/STAR_local_theama_co.crt',
                '/etc/ssl/local.theama.co/STAR_local_theama_co.ca-bundle')
CONFIG_ROOT = Path('/etc/apache2')
DIRECTIVES = {'servername', 'serveralias', 'listen', 'sslengine', 'sslcertificatefile',
              'sslcertificatechainfile', 'alias', 'scriptalias', 'require', 'authmerging',
              'options', 'allowoverride', 'rewriteengine', 'rewritecond', 'rewriterule',
              'redirect', 'sethandler', 'documentroot', 'include', 'includeoptional',
              'order', 'allow', 'deny', 'remoteipheader', 'remoteiptrustedproxy',
              'remoteipinternalproxy', 'accessfilename'}


def run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=12,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if len(p.stdout)+len(p.stderr) > 262144:
            return {'error_type': 'OutputBound'}, ''
        return {'returncode': p.returncode, 'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()}, p.stdout.decode('utf-8', 'replace')
    except Exception as error:
        return {'error_type': type(error).__name__}, ''


def read_config(path):
    actual = path.resolve(strict=True)
    if not actual.is_relative_to(CONFIG_ROOT):
        raise ValueError('config outside approved root')
    info = actual.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 131072:
        raise ValueError('config owner/type/mode/size')
    raw = actual.read_bytes()
    if len(raw) > 131072:
        raise ValueError('config read bound')
    selected = []
    for number, line in enumerate(raw.decode('utf-8', 'replace').splitlines(), 1):
        text = line.strip()
        key = text.split(None, 1)[0].lower() if text else ''
        # Key-file directives, environment variables and credential directives are omitted.
        if key in DIRECTIVES or re.match(r'^</?(?:VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch|IfModule|IfDefine|IfVersion|If|Else|ElseIf|RequireAll|RequireAny|RequireNone)\b', text, re.I):
            if len(text) > 2048:
                raise ValueError('directive length')
            if re.search(r'authorization|password|secret|token|api[_-]?key|://[^/\s]*@', text, re.I):
                selected.append({'line': number, 'redacted_sha256': hashlib.sha256(text.encode()).hexdigest()})
                continue
            selected.append({'line': number, 'text': text})
    return {'path': str(path), 'resolved': str(actual), 'sha256': hashlib.sha256(raw).hexdigest(),
            'size': len(raw), 'selected_directives': selected}


def collect():
    result = {'configuration_mutation': False, 'capture_complete': False, 'findings': [], 'commands': {}}
    if os.geteuid() != 0 or socket.gethostname() != HOST or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != BOOT:
        raise ValueError('root/hostname/boot drift')
    def command(name, argv):
        row, output = run(argv)
        result['commands'][name] = row
        if row.get('returncode') != 0:
            result['findings'].append(name+' unavailable or failed')
        return output
    unit_args = ['/usr/bin/systemctl', 'show', 'apache2.service',
                 '--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,ExecMainStartTimestamp']
    result['service_before'] = command('service_before', unit_args)
    result['version'] = command('version', ['/usr/sbin/apache2ctl', '-v'])
    result['vhosts'] = command('vhosts', ['/usr/sbin/apache2ctl', '-S'])
    result['modules'] = command('modules', ['/usr/sbin/apache2ctl', '-M'])
    includes = command('includes', ['/usr/sbin/apache2ctl', '-t', '-D', 'DUMP_INCLUDES'])
    paths = list(dict.fromkeys(re.findall(r'^\s*\([^\n)]{1,80}\)\s+(/etc/apache2/[^\s]{1,256})\s*$', includes, re.M)))
    if not paths or len(paths) > 96:
        result['findings'].append('loaded include set missing or exceeds 96; no recursive fallback')
        paths = []
    result['configs'] = []
    for name in paths:
        try:
            result['configs'].append(read_config(Path(name)))
        except Exception as error:
            result['configs'].append({'path': name, 'error_type': type(error).__name__})
    result['listeners'] = command('listeners', ['/usr/bin/ss', '-H', '-lntp', '( sport = :80 or sport = :443 )'])
    result['public_certificates'] = []
    for name in PUBLIC_CERTS:
        path = Path(name)
        try:
            actual = path.resolve(strict=True)
            if not actual.is_relative_to('/etc/ssl') or not actual.is_file() or actual.stat().st_size > 65536:
                raise ValueError('public certificate scope')
            raw = actual.read_bytes()
            if len(raw) > 65536 or b'PRIVATE KEY' in raw:
                raise ValueError('public certificate required')
            output = command('public_cert_'+path.suffix, ['/usr/bin/openssl', 'x509', '-in', str(actual),
                             '-noout', '-subject', '-issuer', '-dates', '-fingerprint', '-sha256', '-ext', 'subjectAltName'])
            result['public_certificates'].append({'path': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': output})
        except Exception as error:
            result['public_certificates'].append({'path': name, 'error_type': type(error).__name__})
    result['service_after'] = command('service_after', unit_args)
    result['service_unchanged'] = (result['service_before'] == result['service_after'] and bool(result['service_before'])
                                   and socket.gethostname() == HOST
                                   and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT)
    result['findings'].extend([
        'Parsed files/modules are current disk configuration, not proof that a running process loaded identical bytes.',
        'Selected directives omit unrelated fields; .htaccess, external includes and full authorization merging remain unproven.',
        'Public chain metadata describes its first certificate only; verified client handshakes test presented-chain trust.',
        'No private keys, environment/credential files, application logs or container state were exported.'])
    result['capture_complete'] = result['service_unchanged'] and all(row.get('returncode') == 0 for row in result['commands'].values()) and bool(paths) and all('error_type' not in row for row in result['configs'])
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(collect(), sort_keys=True))
    except Exception as error:
        print(json.dumps({'capture_complete': False, 'error_type': type(error).__name__}))
