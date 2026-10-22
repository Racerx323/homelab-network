"""Real NM 1.42 fixture. Refuses execution outside an isolated systemd container."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('guard', ROOT/'guard.py')
g = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(g)
EVIDENCE = Path('/evidence')


def cmd(argv, timeout=75):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    with (EVIDENCE/'commands.jsonl').open('a') as out:
        out.write(json.dumps({'argv': argv, 'returncode': p.returncode,
                              'stdout': p.stdout, 'stderr': p.stderr})+'\n')
    if p.returncode:
        raise RuntimeError('fixture command failed: '+repr(argv))
    return p.stdout.strip()


def wait_for(check, seconds=20):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise RuntimeError('fixture convergence deadline')


def addresses():
    return json.loads(cmd(['ip', '-j', 'address', 'show', 'dev', 'nmtest0']))[0]['addr_info']


def manager():
    return cmd(['systemctl', 'show', 'NetworkManager.service',
                '--property=MainPID,InvocationID,NRestarts,ActiveState,SubState'])


def setup(uuid):
    if (os.geteuid() != 0 or not Path('/run/.containerenv').exists()
            or Path('/proc/1/comm').read_text().strip() != 'systemd'
            or {r['ifname'] for r in json.loads(cmd(['ip', '-j', 'link']))} != {'lo'}):
        raise RuntimeError('isolated root systemd container with network=none required')
    if not cmd(['nmcli', '--version']).endswith('1.42.4'):
        raise RuntimeError('NM 1.42.4 fixture required')
    Path('/etc/NetworkManager/conf.d/90-fixture.conf').write_text('[main]\ndns=none\nno-auto-default=*\n[keyfile]\nunmanaged-devices=interface-name:router0\n')
    cmd(['systemctl', 'restart', 'NetworkManager.service'])
    cmd(['ip', 'netns', 'add', 'nm-router'])
    cmd(['ip', 'link', 'add', 'nmtest0', 'type', 'veth', 'peer', 'name', 'router0'])
    cmd(['ip', 'link', 'set', 'router0', 'netns', 'nm-router'])
    def router(*args): return cmd(['ip', 'netns', 'exec', 'nm-router', *args])
    router('ip', 'link', 'set', 'lo', 'up')
    router('ip', 'link', 'set', 'router0', 'up')
    for address in ('10.1.0.1/22', '10.1.0.51/22', 'fd36:5aa8:6971:1::1/64',
                    'fd36:5aa8:6971:1::51/64', '2001:db8:1::1/64'):
        router('ip', 'address', 'add', address, 'dev', 'router0')
    router('python3', '-I', '-B', '-c',
           "from pathlib import Path; Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1\\n')")
    wait_for(lambda: all(not a.get('tentative') for row in json.loads(
        router('ip', '-j', '-6', 'address', 'show', 'dev', 'router0')) for a in row['addr_info']))
    Path('/run/fixture-radvd.conf').write_text('''interface router0 {
AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 4; AdvDefaultLifetime 30;
prefix fd36:5aa8:6971:1::/64 { AdvOnLink on; AdvAutonomous on; };
prefix 2001:db8:1::/64 { AdvOnLink on; AdvAutonomous on; };
RDNSS fd36:5aa8:6971:1::55 {};
};
''')
    background=[]
    for name, argv in (
        ('dhcp', ['dnsmasq', '--no-daemon', '--port=0', '--interface=router0', '--bind-interfaces',
                  '--dhcp-range=10.1.3.83,10.1.3.83,255.255.252.0,1h', '--dhcp-option=3,10.1.0.1',
                  '--dhcp-option=6,10.1.0.55', '--dhcp-option=15,local.theama.co',
                  '--dhcp-leasefile=/run/fixture.leases']),
        ('ra', ['radvd', '-n', '-C', '/run/fixture-radvd.conf', '-p', '/run/fixture-radvd.pid', '-m', 'stderr'])):
        stream=(EVIDENCE/(name+'.log')).open('w')
        background.append(subprocess.Popen(['ip', 'netns', 'exec', 'nm-router', *argv], stdout=stream, stderr=subprocess.STDOUT))
    time.sleep(1)
    if any(p.poll() is not None for p in background):
        raise RuntimeError('router fixture failed before client activation')
    cmd(['ip', 'link', 'set', 'nmtest0', 'up'])
    cmd(['nmcli', 'device', 'set', 'nmtest0', 'managed', 'yes'])
    cmd(['nmcli', 'connection', 'add', 'type', 'ethernet', 'ifname', 'nmtest0', 'con-name', 'fixture',
         'connection.uuid', uuid, 'ipv4.method', 'auto', 'ipv6.method', 'auto'])
    cmd(['nmcli', '--wait', '60', 'connection', 'up', 'uuid', uuid])
    def baseline_ready():
        rows = addresses(); local = {a['local'] for a in rows}
        return ('10.1.3.83' in local and any(a.startswith('2001:db8:1:') for a in local)
                and any(a.startswith('fd36:5aa8:6971:1:') for a in local)
                and all(not a.get('tentative') and not a.get('dadfailed') for a in rows))
    wait_for(baseline_ready, seconds=60)
    if any(p.poll() is not None for p in background):
        raise RuntimeError('router fixture failed')
    return background


def acceptance(service_before):
    addr = addresses(); local = {a['local']: a for a in addr}
    route4 = json.loads(cmd(['ip', '-4', '-j', 'route', 'get', '10.1.0.51']))[0]
    route6 = json.loads(cmd(['ip', '-6', '-j', 'route', 'get', 'fd36:5aa8:6971:1::51']))[0]
    default6 = json.loads(cmd(['ip', '-6', '-j', 'route', 'show', 'default']))
    dns = cmd(['nmcli', '-g', 'IP4.DNS,IP6.DNS', 'device', 'show', 'nmtest0']).replace('\\:', ':')
    peers = {}
    for key, address in (('peer4', '10.1.3.83'), ('peer6', 'fd36:5aa8:6971:1::83')):
        cmd(['ip', 'netns', 'exec', 'nm-router', 'ping', '-c', '1', '-W', '2', address])
        peers[key] = True
    return dict(peers, address4='10.1.3.83' in local,
        address6='fd36:5aa8:6971:1::83' in local,
        dad=all(not a.get('tentative') and not a.get('dadfailed') for a in addr),
        routes=(route4.get('prefsrc') == '10.1.3.83' and route6.get('prefsrc') == 'fd36:5aa8:6971:1::83'
                and bool(default6) and any(a.startswith('2001:db8:1:') for a in local)),
        dns='10.1.0.55' in dns and 'fd36:5aa8:6971:1::55' in dns,
        service_continuity=manager() == service_before)


def main():
    mode = sys.argv[1]
    if mode not in ('commit', 'rollback', 'timeout', 'controller-loss', 'failed-acceptance', 'after-modify-failure'):
        raise ValueError('fixture mode')
    EVIDENCE.mkdir(exist_ok=True)
    recipe = json.loads((ROOT/'static-settings.json').read_text()); setup(recipe['original_uuid'])
    baseline = manager()
    guard = g.Checkpoint('nmtest0', recipe['original_uuid'], recipe['settings'],
                         seconds=12 if mode in ('timeout', 'controller-loss') else 90, command=cmd)
    if mode == 'controller-loss':
        pid = os.fork()
        if pid == 0:
            try:
                guard.begin(); guard.apply()
                wait_for(lambda: all(not a.get('tentative') for a in addresses()))
                checks = acceptance(baseline)
                if not all(checks.values()):
                    raise RuntimeError('pre-disconnect acceptance failed')
                (EVIDENCE/'lost-controller-state.json').write_text(json.dumps({
                    'path': guard.path, 'device': guard.device, 'original': guard.original,
                    'deadline': guard.deadline, 'phase': guard.phase, 'checks': checks})+'\n')
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc(); os._exit(1)
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise RuntimeError('disconnected controller failed before exit')
        saved = json.loads((EVIDENCE/'lost-controller-state.json').read_text())
        for key in ('path', 'device', 'original', 'deadline', 'phase'):
            setattr(guard, key, saved[key])
        checks = saved['checks']
    else:
        guard.begin()
        if mode == 'after-modify-failure':
            def injected(argv):
                if argv[:4] == [g.NM, '--wait', '60', 'connection']:
                    raise RuntimeError('injected interruption after actual saved-profile mutation')
                return cmd(argv)
            guard.command = injected
            try:
                guard.apply()
            except RuntimeError as error:
                if 'injected interruption' not in str(error):
                    raise
                guard.command = cmd; guard.rollback()
            else:
                raise RuntimeError('injected interruption was not exercised')
            checks = {'actual_saved_profile_write_then_failure': True}
        else:
            guard.apply()
            wait_for(lambda: all(not a.get('tentative') for a in addresses()))
            checks = acceptance(baseline)
    original = guard.original
    (EVIDENCE/'acceptance.json').write_text(json.dumps(checks, indent=2)+'\n')
    if not all(checks.values()):
        raise RuntimeError('candidate acceptance failed')
    if mode == 'after-modify-failure':
        pass
    elif mode == 'commit':
        guard.commit(lambda: checks)
    elif mode in ('timeout', 'controller-loss'):
        # No checkpoint call until the daemon's own timer expires. In the loss
        # case the process that created/applied the change has actually exited.
        time.sleep(max(0, guard.deadline-time.monotonic())+2)
        guard.command = cmd; guard.confirm_timeout_rollback()
    elif mode == 'failed-acceptance':
        try:
            guard.commit(lambda: dict(checks, peer6=False))
        except ValueError:
            guard.rollback()
        else:
            raise RuntimeError('failed gate was committed')
    else:
        guard.rollback()
    if mode != 'commit':
        assert guard.snapshot() == original
        assert 'fd36:5aa8:6971:1::83' not in {a['local'] for a in addresses()}
    assert manager() == baseline
    assert not guard.checkpoints()
    (EVIDENCE/'result.json').write_text(json.dumps({'scenario': mode, 'passed': True,
        'phase': guard.phase, 'checks': checks, 'nm_version': cmd(['nmcli', '--version']),
        'saved_profile_restored': mode != 'commit', 'production_acceptance': False,
        'controller_process_exited': mode == 'controller-loss'}, indent=2)+'\n')


if __name__ == '__main__':
    main()
