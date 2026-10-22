"""Actual sealed wrapper/SSH/systemd/NetworkManager in a network=none fixture.

Run only inside the isolated root systemd image built with Containerfile.deploy.
Every case creates its own router/client. No production endpoints are reachable.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


native = module('native', ROOT/'test_native_rollback.py')
d = module('deployment', ROOT/'deploy.py')
cmd = native.cmd
EVIDENCE = Path('/evidence')


def wait(check, seconds=30):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        try:
            if check(): return
        except (OSError, RuntimeError, ValueError):
            pass
        time.sleep(0.3)
    raise RuntimeError('outer fixture convergence deadline')


def build_bundle(spec, directory, key):
    files = {name: (ROOT/name).read_bytes() for name in ('deploy.py', 'guard.py', 'static-settings.json')}
    files['tls_probe.py'] = (ROOT/'qualify_dashboard.py').read_bytes()
    files['ca.pem'] = Path('/fixture-tls/server.crt').read_bytes()
    files['known_hosts'] = b'svmf-fixture '+key+b'\n'
    spec['members'] = {name: d.sha(raw) for name, raw in files.items()}
    files['spec.json'] = d.encoded(spec)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as stream:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600
            stream.addfile(info, io.BytesIO(raw))
    raw = archive.getvalue()
    directory.mkdir(mode=0o700)
    for name, data in files.items(): d.write_new(directory/name, data)
    d.write_new(directory/'deployment.tar', raw)
    return d.sha(raw)


def main():
    mode = sys.argv[1]
    if mode not in ('commit', 'controller-loss', 'worker-loss', 'failed-health', 'foreign-drift', 'after-write-failure', 'missing-aaaa'):
        raise ValueError('outer fixture mode')
    EVIDENCE.mkdir(exist_ok=True)
    settings = json.loads((ROOT/'static-settings.json').read_bytes())
    uuid = settings['original_uuid']
    native.setup(uuid)
    router = lambda *argv: cmd(['ip', 'netns', 'exec', 'nm-router', *argv])
    for address in ('10.1.0.55/22', 'fd36:5aa8:6971:1::55/64'):
        router('ip', 'address', 'add', address, 'dev', 'router0')
    # The real system resolver uses a synthetic server reachable over both families.
    dnslog = (EVIDENCE/'dns.log').open('w')
    dns_argv = ['ip', 'netns', 'exec', 'nm-router', 'dnsmasq', '--no-daemon', '--no-resolv',
        '--no-hosts', '--bind-interfaces', '--interface=router0',
        '--host-record=ntp1.local.theama.co,10.1.0.51,fd36:5aa8:6971:1::51']
    dns = subprocess.Popen(dns_argv, stdout=dnslog, stderr=dnslog)
    Path('/etc/resolv.conf').write_text('search local.theama.co\nnameserver 10.1.0.55\nnameserver fd36:5aa8:6971:1::55\n')
    Path('/root/.ssh').mkdir(mode=0o700, exist_ok=True)
    cmd(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', '/root/.ssh/id_ed25519'])
    Path('/root/.ssh/authorized_keys').write_bytes(Path('/root/.ssh/id_ed25519.pub').read_bytes())
    Path('/etc/ssh/sshd_config.d/99-fixture.conf').write_text('PermitRootLogin prohibit-password\nPasswordAuthentication no\n')
    cmd(['systemctl', 'start', 'ssh.service'])
    Path('/fixture-tls').mkdir(mode=0o700)
    cmd(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '2',
         '-keyout', '/fixture-tls/server.key', '-out', '/fixture-tls/server.crt',
         '-subj', '/CN=munin.local.theama.co', '-addext', 'subjectAltName=DNS:munin.local.theama.co'])
    Path('/etc/systemd/system/svmf-fixture-app.service').write_text('[Service]\nExecStart=/usr/bin/python3 -I -B '+str(ROOT/'fixture_apps.py')+'\n')
    cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'start', 'svmf-fixture-app.service'])
    wait(lambda: cmd(['getent', 'ahostsv4', 'ntp1.local.theama.co']))
    wait(lambda: native.addresses() and native.manager())
    mac = Path('/sys/class/net/nmtest0/address').read_text().strip()
    filename = ''
    for row in cmd(['nmcli', '-t', '-f', 'UUID,FILENAME', 'connection', 'show']).splitlines():
        if row.partition(':')[0] == uuid: filename = row.partition(':')[2]
    # Wait for any activation-time keyfile write before sealing its exact bytes.
    time.sleep(2)
    spec = {'schema': 1, 'operation_id': 'svmf-network-fixture-'+mode,
        'prepared_epoch': int(time.time()), 'expires_epoch': int(time.time())+3600,
        'hostname': socket.gethostname(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'host_key_alias': 'svmf-fixture', 'user': 'root', 'interface': 'nmtest0', 'uuid': uuid,
        'nm_version': 'nmcli tool, version 1.42.4', 'profile': filename,
        'profile_sha256': d.sha(Path(filename).read_bytes()), 'mac': mac, 'checkpoint_seconds': 100,
        'manager': d.unit('NetworkManager.service'), 'settings': settings['settings'],
        'addresses': ['10.1.3.83', 'fd36:5aa8:6971:1::83'],
        'original_sources': [json.loads(cmd(['ip', family, '-j', 'route', 'get', dest]))[0]['prefsrc']
             for family, dest in (('-4', '10.1.0.51'), ('-6', 'fd36:5aa8:6971:1::51'))],
        'ntp_addresses': ['10.1.0.51', 'fd36:5aa8:6971:1::51'], 'gateway4': '10.1.0.1',
        'dns': ['10.1.0.55', 'fd36:5aa8:6971:1::55'], 'search': 'local.theama.co',
        'resolver_name': 'ntp1.local.theama.co',
        'dashboard_paths': ['/', '/static/style-new.css', '/munin-cgi/munin-cgi-graph/J1-SVMF/J1-SVMF/apache_accesses-day.png'],
        'dashboard_host': 'munin.local.theama.co',
        'dashboard_leaf_sha256': d.sha(__import__('ssl').PEM_cert_to_DER_cert(Path('/fixture-tls/server.crt').read_text())),
        'apprise_port': 8000, 'mailrise_port': 8025,
        'units': ['NetworkManager.service', 'ssh.service', 'svmf-fixture-app.service']}
    key = b' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_bytes().split()[:2])
    directory = EVIDENCE/'controller'
    digest = build_bundle(spec, directory, key)
    before = d.snapshot(spec)
    d.save(EVIDENCE/'before.json', before)
    if mode == 'missing-aaaa':
        dns.terminate(); dns.wait(timeout=5)
        dns = subprocess.Popen(dns_argv[:-1]+['--host-record=ntp1.local.theama.co,10.1.0.51'], stdout=dnslog, stderr=dnslog)
        wait(lambda: cmd(['getent', 'ahostsv4', 'ntp1.local.theama.co']))
        mapped = cmd(['getent', 'ahostsv6', 'ntp1.local.theama.co'])
        if not mapped or any(not line.startswith('::ffff:10.1.0.51 ') for line in mapped.splitlines()):
            raise RuntimeError('fixture did not reproduce successful mapped IPv4 fallback')
        d.save(EVIDENCE/'mapped-lookup.json', {'returncode': 0, 'stdout': mapped})
    log = (EVIDENCE/'controller.log').open('wb')
    controller = subprocess.Popen(['ip', 'netns', 'exec', 'nm-router', '/usr/bin/python3', '-I', '-B',
        str(directory/'deploy.py'), 'execute', '--directory', str(directory), '--sha256', digest],
        stdout=log, stderr=log, start_new_session=True)
    d.save(EVIDENCE/'invocation.json', {'argv': controller.args, 'pid': controller.pid, 'bundle_sha256': digest,
        'source_sha256': {name: d.sha((ROOT/name).read_bytes()) for name in ('deploy.py', 'guard.py', 'qualify_dashboard.py', 'test_native_deploy.py', 'fixture_apps.py')}})
    target = d.STATE/spec['operation_id']
    def state():
        return json.loads((target/'state.json').read_bytes()) if (target/'state.json').exists() else {}
    if mode == 'missing-aaaa':
        controller.wait(timeout=150)
        if controller.returncode != 2 or state().get('phase') != 'preflight_failed' or 'resolver IPv6' not in state().get('error', ''):
            raise RuntimeError('missing AAAA did not fail closed before mutation')
        checkpoint = d.guard_module().Checkpoint(spec['interface'], spec['uuid'], spec['settings'])
        if checkpoint.checkpoints() or (target/'original.nmconnection').exists() or d.sha(Path(filename).read_bytes()) != spec['profile_sha256']:
            raise RuntimeError('failed DNS preflight armed, backed up or changed profile')
        # Restore only synthetic DNS so independent SSH can inspect original networking.
        dns.terminate(); dns.wait(timeout=5)
        dns = subprocess.Popen(dns_argv, stdout=dnslog, stderr=dnslog)
        wait(lambda: d.system_resolver(spec, 6))
        independent = []
        for family, address in zip((4, 6), spec['original_sources']):
            probe = "import importlib.util,json,sys; from pathlib import Path; s=importlib.util.spec_from_file_location('d',sys.argv[1]); d=importlib.util.module_from_spec(s); s.loader.exec_module(d); p=Path(sys.argv[2]); spec=json.loads((p/'spec.json').read_bytes()); print(json.dumps({'ssh':d.remote(spec,p,int(sys.argv[3]),sys.argv[4],'readback'),'https':d.dashboard_https(spec,p,sys.argv[4])}))"
            row = json.loads(router('python3', '-I', '-B', '-c', probe, str(ROOT/'deploy.py'), str(directory), str(family), address))
            gates = d.checks(spec, before, row['ssh']['snapshot'], False)
            if not all(gates.values()) or row['ssh']['checkpoints']:
                raise RuntimeError('original network not independently preserved')
            independent.append(row)
        d.save(EVIDENCE/'independent-preflight.json', independent)
        d.save(EVIDENCE/'result.json', {'passed': True, 'mode': mode, 'phase': state()['phase'],
            'no_checkpoint_or_backup': True, 'profile_unchanged': True, 'controller_returncode': controller.returncode})
        return
    # Intercept before the controller can confirm: temporarily block new IPv6 SSH
    # by stopping the controller process group as soon as the supervisor is staged.
    if mode != 'commit':
        wait(lambda: state().get('phase') in ('guarded', 'write_intent', 'awaiting_confirmation') or controller.poll() is not None)
        os.killpg(controller.pid, signal.SIGSTOP)
        if mode == 'after-write-failure':
            # Interrupt the actual worker after its candidate keyfile write.
            wait(lambda: 'method=manual' in Path(filename).read_text())
            cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=KILL', spec['operation_id']+'.service'])
        else:
            wait(lambda: state().get('phase') in ('awaiting_confirmation', 'preflight_failed', 'recovery_held'))
            if state().get('phase') != 'awaiting_confirmation':
                raise RuntimeError('worker failed before fault injection')
            if mode == 'worker-loss':
                cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=KILL', spec['operation_id']+'.service'])
            elif mode == 'failed-health':
                cmd(['systemctl', 'stop', 'svmf-fixture-app.service'])
            elif mode == 'foreign-drift':
                cmd(['nmcli', 'connection', 'modify', 'uuid', uuid, 'connection.id', 'foreign-profile'])
        os.killpg(controller.pid, signal.SIGKILL)
        controller.wait(timeout=10)
        # Exercise the actual read-only continuation entry point after loss.
        inspect = ['ip', 'netns', 'exec', 'nm-router', 'python3', '-I', '-B', str(directory/'deploy.py'),
            'inspect', '--directory', str(directory), '--sha256', digest]
        with (EVIDENCE/'inspection.log').open('wb') as stream:
            subprocess.run(inspect, stdout=stream, stderr=stream, check=True, timeout=90)
        if mode in ('controller-loss', 'failed-health', 'foreign-drift'):
            wait(lambda: state().get('phase') in d.TERMINAL, seconds=130)
        else:
            time.sleep(max(0, state()['deadline']-time.monotonic()+3))
        if mode in ('failed-health', 'foreign-drift'):
            if state().get('phase') != 'recovery_held': raise RuntimeError('unsafe recovery acceptance')
            # Restore only fixture-induced service fault; allow native checkpoint
            # timeout to revert foreign profile drift. This is never production recovery.
            if mode == 'failed-health': cmd(['systemctl', 'start', 'svmf-fixture-app.service'])
            time.sleep(max(0, state()['deadline']-time.monotonic()+3))
        deadline = time.monotonic()+60
        while True:
            try:
                after = d.snapshot(spec)
                gates = d.checks(spec, before, after, False)
                # The test deliberately restarted a fixture application; record
                # that fault, and verify the network independently below.
                network = {k: v for k, v in gates.items() if k != 'service_continuity'}
                if all(network.values()): break
            except Exception as error:
                d.save(EVIDENCE/'recovery-readback-error.json', {'type': type(error).__name__, 'error': str(error)})
            if time.monotonic() >= deadline: raise RuntimeError('independent recovery failed')
            time.sleep(1)
        d.save(EVIDENCE/'recovery.json', {'gates': gates, 'after': after})
        probe = "import importlib.util,json,sys; from pathlib import Path; s=importlib.util.spec_from_file_location('d',sys.argv[1]); d=importlib.util.module_from_spec(s); s.loader.exec_module(d); p=Path(sys.argv[2]); spec=json.loads((p/'spec.json').read_bytes()); results=[{'ssh':d.remote(spec,p,f,a,'readback'),'https':d.dashboard_https(spec,p,a)} for f,a in zip((4,6),spec['original_sources'])]; print(json.dumps(results))"
        independent = json.loads(router('python3', '-I', '-B', '-c', probe, str(ROOT/'deploy.py'), str(directory)))
        if any(row['ssh']['state']['bundle_sha256'] != digest or row['ssh']['checkpoints'] or not all(v for k,v in row['ssh']['original_checks'].items() if k != 'service_continuity') for row in independent):
            raise RuntimeError('independent SSH recovery failed')
        d.save(EVIDENCE/'independent-recovery.json', independent)
    else:
        controller.wait(timeout=150)
        if controller.returncode != 0 or state().get('phase') != 'committed':
            raise RuntimeError('outer commit failed')
        after = d.snapshot(spec)
        gates = d.checks(spec, before, after, True)
        if not all(gates.values()): raise RuntimeError('independent commit readback failed')
        d.save(EVIDENCE/'commit.json', {'gates': gates, 'after': after})
    checkpoint = d.guard_module().Checkpoint(spec['interface'], spec['uuid'], spec['settings'])
    if checkpoint.checkpoints(): raise RuntimeError('native checkpoint leaked')
    backup = (target/'original.nmconnection').read_bytes()
    if d.sha(backup) != spec['profile_sha256']: raise RuntimeError('backup not exact')
    d.save(EVIDENCE/'result.json', {'passed': True, 'mode': mode, 'phase': state()['phase'],
        'exact_backup': True, 'controller_returncode': controller.returncode})


if __name__ == '__main__':
    main()
