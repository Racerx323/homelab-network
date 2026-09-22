#!/usr/bin/env python3
"""Fixed-path packet trial checks and cleanup, never modifies guard policy."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_guard as guard
from network_policy import normalized_table, digest

BASE = Path('/var/lib/nautobot-packet-trial')
UNIT = 'nautobot-packet-trial.service'


def run(args):
    return guard.run(args)


def verify_guard():
    expected = json.loads(guard.trusted(BASE/'guard-inputs.json'))
    for name, sha in expected['files'].items():
        if hashlib.sha256(guard.trusted(Path(name)).encode()).hexdigest() != sha:
            raise RuntimeError('installed guard file drift')
    rules = json.loads(run(['nft', '-j', 'list', 'ruleset']))
    if digest(normalized_table(rules)) != expected['table_digest']:
        raise RuntimeError('rules drift')
    return rules


def counters(rules):
    result = {}
    for item in rules['nftables']:
        rule = item.get('rule', {})
        if rule.get('comment') in ['allow-v4', 'deny-v4', 'allow-v6', 'deny-v6']:
            result[rule['comment']] = next(x['counter']['packets'] for x in rule['expr'] if 'counter' in x)
    if set(result) != {'allow-v4', 'deny-v4', 'allow-v6', 'deny-v6'}:
        raise RuntimeError('counter set incomplete')
    return result


def main(action):
    if os.geteuid() != 0 or run(['hostname','-s']).strip() != 'j2-svpi4mf':
        raise RuntimeError('wrong identity')
    state_path = BASE/'state.json'
    if action == 'prepare':
        if state_path.exists():
            raise RuntimeError('existing trial state')
        if run(['systemctl','show',UNIT,'-p','LoadState','--value']).strip() != 'not-found':
            raise RuntimeError('existing trial unit')
        report=json.loads(run(['/usr/bin/python3','-I','/var/lib/nautobot-backend-install/install_state.py','report']))
        if report['status'] != 'accepted':
            raise RuntimeError('guard unaccepted')
        verify_guard()
        value={'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'status':'prepared'}
        state_path.write_text(json.dumps(value));state_path.chmod(0o600)
    elif action in ['ready','snapshot','cleanup']:
        state=json.loads(guard.trusted(state_path))
        if state['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            raise RuntimeError('boot drift')
        if action == 'ready':
            props = dict(x.split('=',1) for x in run(['systemctl','show',UNIT,'-p','ActiveState','-p','MainPID','-p','User','-p','RuntimeMaxUSec']).splitlines())
            if props.get('ActiveState') != 'active' or props.get('User') != 'nautobot' or props.get('RuntimeMaxUSec') != '2min 55s' or int(props.get('MainPID','0')) <= 0:
                raise RuntimeError('listener service not ready or bounded')
            lines=run(['ss','-H','-ltnp','sport','=',':8080']).splitlines()
            addresses={x.split()[3].replace('[','').replace(']','') for x in lines}
            if addresses != {'10.1.2.170:8080','fd36:5aa8:6971:1::170:8080','127.0.0.1:8080'} or len(lines)!=3:
                raise RuntimeError('listener bind mismatch')
            if any('pid='+props['MainPID']+',' not in line for line in lines):
                raise RuntimeError('listener process mismatch')
        if action == 'cleanup':
            run(['systemctl','stop',UNIT])
            if run(['ss','-H','-ltn','sport','=',':8080']).strip():
                raise RuntimeError('listener remains; retain guard')
            if run(['systemctl','show',UNIT,'-p','MainPID','--value']).strip() != '0':
                raise RuntimeError('process remains')
            report=json.loads(run(['/usr/bin/python3','-I','/var/lib/nautobot-backend-install/install_state.py','report']))
            if report['status'] != 'accepted':
                raise RuntimeError('post-cleanup baseline failed')
            verify_guard()
            state['status']='cleaned';state_path.write_text(json.dumps(state));state_path.chmod(0o600)
        rules=verify_guard()
        print(json.dumps({'status':state['status'],'sampled_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'counters':counters(rules),
                          'unit':run(['systemctl','show',UNIT,'-p','ActiveState','-p','MainPID','-p','User','-p','RuntimeMaxUSec']),
                          'listeners':run(['ss','-H','-ltnp','sport','=',':8080'])}))
    else:
        raise ValueError('invalid action')


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception as exc:
        print('PACKET_TRIAL_FAILED: '+type(exc).__name__+': '+str(exc)[:300], file=sys.stderr)
        sys.exit(1)
