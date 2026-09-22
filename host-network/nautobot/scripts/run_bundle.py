#!/usr/bin/env python3
"""Verify exact frozen standby-route bundle, then delegate execution to Ansible."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from health_watch import Monitor, gate


def verify(bundle, approved):
    raw = (bundle / 'bundle.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != approved:
        raise ValueError('authorization hash mismatch')
    manifest = json.loads(raw)
    if manifest['kind'] != 'standby_route_retry' or manifest['execution_ready'] is not True:
        raise ValueError('not a route deployment bundle')
    for name, expected in manifest['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe bundle path')
        path = bundle / relative
        if any(p.is_symlink() for p in [path, *path.parents]) or not path.is_file():
            raise ValueError('unsafe bundle artifact')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('bundle artifact mismatch')
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--approved-sha256', required=True)
    args = parser.parse_args()
    manifest = verify(args.bundle.resolve(), args.approved_sha256)
    root = Path(tempfile.mkdtemp(prefix='nautobot-route-execution-', dir='/tmp'))
    os.chmod(root,0o700)
    for name in manifest['files']:
        dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(args.bundle/name,dest)
    (root/'bundle.json').write_bytes((args.bundle/'bundle.json').read_bytes())
    verify(root,args.approved_sha256)
    env = {'PATH':os.environ['PATH'], 'HOME':os.environ['HOME'], 'LC_ALL':'C.UTF-8',
           'ANSIBLE_HOST_KEY_CHECKING':'True','ANSIBLE_LOCAL_TEMP':str(root/'ansible-tmp'),
           'ANSIBLE_CONFIG':str(root/'ansible.cfg')}
    if 'SSH_AUTH_SOCK' in os.environ:env['SSH_AUTH_SOCK']=os.environ['SSH_AUTH_SOCK']
    (root/'ansible.cfg').write_text('[defaults]\nhost_key_checking=True\nretry_files_enabled=False\n')
    cmd=['ansible-playbook','-i','10.1.0.54,','-u','pi','ansible/route.yaml','--extra-vars',
         json.dumps({'candidate_execution_enabled':True,'route_host':'pihole00',
                     'route_uuid':'3078e1cc-2e08-3745-b5e4-a60426628c39',
                     'route_qualification_verified':True,'ha_standby_verified':True,'controller_evidence':str(root)})]
    monitor = Monitor(root)
    monitor.start()
    accepted = False
    result_rc = None
    report_rc = None
    error = None
    try:
        gate(root, 'healthy', timeout=15)
        with open(root/'stdout.log','w') as stdout, open(root/'stderr.log','w') as stderr:
            result = subprocess.run(cmd,cwd=root,env=env,stdout=stdout,stderr=stderr,timeout=600)
        result_rc = result.returncode
        report = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                 '-o', 'ConnectTimeout=10', 'pi@10.1.0.54',
                                 'cd / && sudo -n /usr/bin/python3 -I /usr/local/lib/nautobot-network/proxy_route.py report pihole00 3078e1cc-2e08-3745-b5e4-a60426628c39'],
                                text=True, capture_output=True, timeout=40)
        report_rc = report.returncode
        (root/'node-report.json').write_text(report.stdout[:20000])
        (root/'node-report.stderr').write_text(report.stderr[:2000])
        if report_rc == 0:
            accepted = json.loads(report.stdout).get('status') == 'accepted'
        if accepted:
            gate(root, 'stable', timeout=10)
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)[:1000]
        accepted = False
    finally:
        monitor.close()
        (root/'result.json').write_text(json.dumps({'returncode':result_rc,
            'node_report_rc':report_rc,'accepted':accepted,'bundle':args.approved_sha256,
            'error':error,'recovery_note':'On interruption or unreachable host, retain the node watchdog and inspect its outcome; no automatic rerun.'}))
    print('Protected evidence: '+str(root))
    raise SystemExit(0 if result_rc == 0 and accepted else 1)


if __name__ == '__main__':main()
