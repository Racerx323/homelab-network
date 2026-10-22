"""Bounded read-only svmf readiness capture; no profile or service changes."""
import ipaddress
import gzip
import json
import os
from pathlib import Path
import re
import socket
import stat

UUID = '2cad90ef-210e-329a-bc55-9e23fa8160dd'
FIELDS = ('connection.id,connection.uuid,connection.interface-name,connection.autoconnect,'
          'ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.dns-search,'
          'ipv4.ignore-auto-dns,ipv4.routes,ipv4.ignore-auto-routes,ipv4.never-default,'
          'ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.dns,ipv6.dns-search,'
          'ipv6.ignore-auto-dns,ipv6.routes,ipv6.ignore-auto-routes,ipv6.never-default,'
          'ipv6.addr-gen-mode,ipv6.ip6-privacy')


def selected_fields(raw, allowed):
    result = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(':')
        if not sep or key not in allowed or key in result:
            raise ValueError('unexpected or duplicate selected field')
        value = value.strip()
        if len(value) > 4096 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError('unsafe selected field')
        result[key] = value
    if set(result) != set(allowed):
        raise ValueError('missing selected field')
    return result


def metadata(path):
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        return {'indirect': True}
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'missing': True}
    return {'regular': stat.S_ISREG(info.st_mode), 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'size': info.st_size, 'inode': info.st_ino}


def firewall_summary(raw):
    """Export only typed packet matches/verdicts; omit comments and commands."""
    entries = json.loads(raw)['nftables']
    if not isinstance(entries, list) or len(entries) > 2048:
        raise ValueError('firewall entry bound')
    result = {'chains': [], 'rules': [], 'unresolved_expressions': 0, 'sets': 0}
    def literal(value):
        if type(value) is int and 0 <= value <= 65535:
            return value
        if isinstance(value, str):
            try:
                return str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                return None
        if isinstance(value, dict) and set(value) == {'prefix'}:
            p = value['prefix']
            try:
                return str(ipaddress.ip_network(str(p['addr'])+'/'+str(p['len']), strict=False))
            except (ValueError, KeyError, TypeError):
                return None
        return None
    for entry in entries:
        if 'chain' in entry:
            chain = entry['chain']
            result['chains'].append({k: chain[k] for k in ('family', 'hook', 'policy')
                                     if chain.get(k) in ('ip', 'ip6', 'inet', 'input', 'output',
                                                        'forward', 'accept', 'drop')})
        if 'set' in entry:
            result['sets'] += 1
        if 'rule' not in entry:
            continue
        row = []
        for expr in entry['rule'].get('expr', []):
            if 'match' in expr:
                match = expr['match']; payload = match.get('left', {}).get('payload', {})
                right = literal(match.get('right'))
                if (payload.get('protocol') in ('ip', 'ip6', 'tcp', 'udp')
                        and payload.get('field') in ('saddr', 'daddr', 'sport', 'dport')
                        and match.get('op') in ('==', '!=', 'in') and right is not None):
                    row.append({'protocol': payload['protocol'], 'field': payload['field'],
                                'op': match['op'], 'value': right})
                else:
                    result['unresolved_expressions'] += 1
            elif set(expr) <= {'accept', 'drop', 'reject', 'counter'}:
                row.extend({'verdict': key} for key in expr if key != 'counter')
            else:
                result['unresolved_expressions'] += 1
        result['rules'].append(row)
    # This projection is evidence, never a complete policy or permission proof.
    result['complete_policy_proof'] = False
    return result


def collect(spec, h):
    result = {'operation_id': spec['operation_id'], 'spec_sha256': h.sha(h.encoded(spec)),
              'capture_complete': False, 'commands': {}, 'findings': [],
              'static_configuration_accepted': False, 'recovery_qualified': False,
              'address_available_proven': False, 'target_mutation': False}
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
    def command(label, argv, optional=False):
        row = h.bounded(argv, timeout=12, limit=262144, env=env)
        # Do not export raw stderr or command output from optional tools.
        result['commands'][label] = {'argv': argv, 'returncode': row.get('returncode'),
                                     'failed': bool(row.get('error'))}
        if row.get('error') or row.get('returncode') != 0:
            if optional:
                result['findings'].append(label+' unavailable; separate follow-up required')
                return None
            raise ValueError('required command failed: '+label)
        return row['stdout']
    def identity():
        if (os.geteuid() != 0 or socket.gethostname() != spec['hostname']
                or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != spec['boot_id']):
            raise ValueError('master root/host/boot drift')
        active = command('active_uuid', ['/usr/bin/nmcli', '-t', '-f', 'UUID,DEVICE',
                                         'connection', 'show', '--active'])
        if [x for x in active.splitlines() if x.endswith(':eth0')] != [UUID+':eth0']:
            raise ValueError('active Ethernet UUID drift')
        return command('manager_identity', ['/usr/bin/systemctl', 'show', 'NetworkManager.service',
                       '--property=MainPID,InvocationID,NRestarts,ActiveState,SubState'])
    def settings(label):
        return selected_fields(command(label, ['/usr/bin/nmcli', '-m', 'multiline', '-f',
                                                FIELDS, 'connection', 'show', UUID]), FIELDS.split(','))
    try:
        result['manager_before'] = identity()
        result['settings'] = settings('settings_before')
        result['nm_version'] = command('nm_version', ['/usr/bin/nmcli', '--version']).strip()
        names = command('profile_filename', ['/usr/bin/nmcli', '-t', '-f', 'UUID,FILENAME',
                                             'connection', 'show'])
        paths = [x.partition(':')[2] for x in names.splitlines() if x.partition(':')[0] == UUID]
        if len(paths) != 1 or not re.fullmatch(r'/etc/NetworkManager/system-connections/[^/\x00-\x1f]{1,160}\.nmconnection', paths[0]):
            raise ValueError('persistent selected profile path drift')
        result['profile'] = {'path': paths[0], 'metadata': metadata(Path(paths[0]))}
        info = result['profile']['metadata']
        if not info.get('regular') or info['uid'] != 0 or info['mode'] & 0o077:
            raise ValueError('protected persistent profile required')
        for label, args in (('addresses', ['-j', 'address', 'show', 'dev', 'eth0']),
                            ('routes4', ['-4', '-j', 'route', 'show', 'table', 'all']),
                            ('routes6', ['-6', '-j', 'route', 'show', 'table', 'all']),
                            ('neighbors', ['-6', '-j', 'neighbor', 'show', 'dev', 'eth0']),
                            ('node_route4', ['-4', '-j', 'route', 'get', '10.1.0.51']),
                            ('node_route6', ['-6', '-j', 'route', 'get', 'fd36:5aa8:6971:1::51'])):
            value = json.loads(command(label, ['/usr/sbin/ip', *args]))
            if not isinstance(value, list) or len(value) > 512:
                raise ValueError('network row bound')
            result[label] = value
        # Fixed selected runtime fields include actual gateway and DNS, not secrets.
        result['runtime_ip'] = command('runtime_ip', ['/usr/bin/nmcli', '-m', 'multiline',
                                                     '-f', 'IP4,IP6', 'device', 'show', 'eth0'])
        result['checkpoint_help'] = command('checkpoint_help', ['/usr/bin/nmcli', 'device', 'help'], True)
        result['checkpoint_help_mentions_checkpoint'] = 'checkpoint' in (result['checkpoint_help'] or '').lower()
        result['listeners'] = command('listeners', ['/usr/bin/ss', '-H', '-lnt'])
        result['units'] = {}
        for unit in ('cron.service', 'munin-node.service', 'apache2.service', 'nginx.service', 'ssh.service'):
            result['units'][unit] = command('unit_'+unit, ['/usr/bin/systemctl', 'show', unit,
                '--property=Id,LoadState,MainPID,InvocationID,NRestarts,ActiveState,SubState'], True)
        raw = command('firewall', ['/usr/sbin/nft', '-j', 'list', 'ruleset'], True)
        if raw is not None:
            result['firewall'] = firewall_summary(raw)
        result['findings'].extend([
            'Controller allocation/conflict check needs its own approved controller scope.',
            'Neighbor silence is not address availability; no active probe or DAD was run.',
            'No checkpoint was created; timed rollback and independent recovery access remain unqualified.',
            'Web configuration, container health and external dashboard reachability remain separate checks.'])
        result['manager_after'] = identity()
        if result['manager_before'] != result['manager_after'] or result['settings'] != settings('settings_after'):
            raise ValueError('manager or selected settings changed during capture')
        result['capture_complete'] = True
    except Exception as error:
        # Fixed failure labels only; never include arbitrary parser input.
        result['error'] = str(error) if isinstance(error, ValueError) else type(error).__name__
    return result


def help_excerpt(raw):
    lines = raw.splitlines()
    indexes = {j for i, line in enumerate(lines) if 'checkpoint' in line.lower()
               for j in range(max(0, i-2), min(len(lines), i+16))}
    if len(indexes) > 240:
        raise ValueError('checkpoint documentation excerpt bound')
    return '\n'.join(lines[i] for i in sorted(indexes))


def collect_recovery(spec, h):
    result = {'operation_id': spec['operation_id'], 'spec_sha256': h.sha(h.encoded(spec)),
              'capture_complete': False, 'target_mutation': False,
              'timed_recovery_qualified': False, 'independent_recovery_access_verified': False}
    def command(argv):
        row = h.bounded(argv, timeout=12, limit=262144,
                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if row.get('error') or row.get('returncode') != 0:
            raise ValueError('required recovery-readiness command failed')
        return row
    def identity():
        if (os.geteuid() != 0 or socket.gethostname() != spec['hostname']
                or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != spec['boot_id']):
            raise ValueError('master root/host/boot drift')
        active = command(['/usr/bin/nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active'])['stdout']
        if [x for x in active.splitlines() if x.endswith(':eth0')] != [UUID+':eth0']:
            raise ValueError('active Ethernet UUID drift')
        return command(['/usr/bin/systemctl', 'show', 'NetworkManager.service',
                        '--property=MainPID,InvocationID,NRestarts,ActiveState,SubState'])['stdout']
    try:
        result['manager_before'] = identity()
        result['version'] = command(['/usr/bin/nmcli', '--version'])['stdout'].strip()
        row = command(['/usr/bin/nmcli', 'device', 'help'])
        result['device_help'] = {key: help_excerpt(row.get(key, '')) for key in ('stdout', 'stderr')}
        manuals = []
        for name in ('/usr/share/man/man1/nmcli.1.gz', '/usr/share/man/man1/nmcli.1'):
            path = Path(name); info = metadata(path)
            if info.get('missing'):
                continue
            if not info.get('regular') or info.get('uid') != 0 or info.get('mode', 0) & 0o022 or info['size'] > 1048576:
                raise ValueError('unsafe installed manual')
            with (gzip.open(path, 'rb') if name.endswith('.gz') else path.open('rb')) as stream:
                raw = stream.read(1048577)
            if len(raw) > 1048576:
                raise ValueError('manual expansion bound')
            manuals.append({'path': name, 'metadata': info,
                            'checkpoint_excerpt': help_excerpt(raw.decode('utf-8', errors='replace'))})
        result['manuals'] = manuals
        result['checkpoint_documented'] = any(result['device_help'].values()) or any(x['checkpoint_excerpt'] for x in manuals)
        result['manager_after'] = identity()
        if result['manager_before'] != result['manager_after']:
            raise ValueError('NetworkManager identity changed')
        result['capture_complete'] = True
    except Exception as error:
        result['error'] = str(error) if isinstance(error, ValueError) else type(error).__name__
    return result


def review(spec):
    if spec['mode'] == 'master-recovery-readiness':
        return f'''# Read-only master recovery-capability review

Target pi@10.1.3.83, pinned alias svmf.local.theama.co, hostname
{spec['hostname']}, boot {spec['boot_id']} and active Ethernet UUID {UUID}.
Baseline: completed static-network readiness inspection; do not replay it.

Read nmcli version and `nmcli device help`, retaining checkpoint-related public
help excerpts from BOTH stdout and stderr. Read only protected installed
/usr/share/man/man1/nmcli.1.gz or nmcli.1, bounded to 1 MiB after decompression;
export checkpoint-related excerpts, not the whole manual. Match host/boot/UUID
and NetworkManager service identity before/after. Missing documentation is an
unknown finding, not proof that checkpoint support is absent.

No checkpoint creation/rollback, profile/config/backup read or write, activation,
renewal, service restart/reload, address probe, controller contact, HTTP/container
action, credentials, plugins, notifications or reboot. Native documentation can
qualify syntax/capability evidence only: timed recovery and independent recovery
access remain unaccepted and require later guarded qualification. No mutation
needs restoration. Single use, 24-hour approval window and source integrity
checks apply. Preparation contacts no target. After exact archive approval:

```bash
python3 -I -B ntpsec/scripts/run-munin-prerequisites.py execute --directory OUTPUT --sha256 APPROVED_SHA256
```

From homelab-ntp; OUTPUT is this directory. Bind approval to sealing.json SHA-256.
'''
    return f'''# Read-only static-network readiness review

Target pi@10.1.3.83, strict host-key alias svmf.local.theama.co; require accepted
hostname {spec['hostname']}, boot {spec['boot_id']} and Ethernet UUID {UUID}.
Desired future addresses: 10.1.3.83/22 and fd36:5aa8:6971:1::83/64.

Read selected non-secret NetworkManager profile/runtime address, gateway, DNS,
route and privacy fields; protected persistent-profile metadata only (no content
or content hash). Read eth0 addresses, IPv4/IPv6 routes, passive IPv6 neighbors,
routes to both fixed NTP node addresses, TCP listener endpoints and selected
service identity fields. Read nmcli device help only: do not create a checkpoint.
Read local nftables JSON in memory; export typed packet matches/verdicts only,
omitting comments, commands and named sets. Unsupported expressions are findings;
this projection cannot establish complete policy or effective permission.

No profile changes, reapply, activation, checkpoint creation, renewal, DNS queries,
address probes, controller contact, container commands, plugins, HTTP requests,
notifications, firewall mutation, service changes, backup creation or reboot.
Optional missing tools are findings, never approval of unknown settings/recovery.
Before/after host/boot/UUID, NetworkManager identity and selected settings must
match. Completion means captured evidence only; static configuration, address
availability and timed rollback remain unaccepted. No restoration is applicable.
Source/IPAM/review inputs are sealed; no raw profile, secret_key, machine-id,
unrestricted web/container configuration or secret values are read.

Preparation contacts no target. Execution is single-use and expires after 24h;
source or input changes require a new seal and approval. Output is private.
This review does not authorize the future static-network mutation or DNS/Munin
deployment. Command from homelab-ntp after exact archive approval:

```bash
python3 -I -B ntpsec/scripts/run-munin-prerequisites.py execute --directory OUTPUT --sha256 APPROVED_SHA256
```

OUTPUT is this review directory. Approve the inspection.tar SHA-256 in sealing.json.
'''
