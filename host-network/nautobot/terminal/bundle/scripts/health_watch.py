#!/usr/bin/env python3
"""Bounded controller observations and gates for one standby route operation."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
VIPS = {'10.1.0.55','10.1.0.56','fd36:5aa8:6971:1::55','fd36:5aa8:6971:1::56'}
NODES = {'primary': ('10.1.0.53','fd36:5aa8:6971:1::53','pihole0.local.theama.co','j1-svpihole0'),
         'standby': ('10.1.0.54','fd36:5aa8:6971:1::54','pihole00.local.theama.co','j1-svpihole00')}


def command(args, data=None):
    try:
        r = subprocess.run(args,input=data,text=True,capture_output=True,timeout=4)
        return {'rc':r.returncode,'stdout':r.stdout[:20000]}
    except subprocess.TimeoutExpired:
        return {'rc':124,'stdout':''}


def dns(address):
    r = command(['dig','@'+address,'j2-svpi4mf.local.theama.co','A','+time=2','+tries=1','+noall','+comments','+answer'])
    answers = [line.split() for line in r['stdout'].splitlines() if line and not line.startswith(';')]
    r['ok'] = r['rc'] == 0 and 'status: NOERROR' in r['stdout'] and len(answers) == 1 and answers[0][-2:] == ['A','10.1.2.170']
    return r


def https(address, name, path='/healthz'):
    r = command(['curl','--noproxy','*','--silent','--fail','--connect-timeout','1','--max-time','2',
                 '--max-redirs','0','--output','/dev/null','--write-out','%{http_code}',
                 '--resolve',name+':443:'+('['+address+']' if ':' in address else address),
                 'https://'+name+path])
    r['ok'] = r['rc'] == 0 and r['stdout'] == '204'
    return r


def node(address, extended=False):
    r = command(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=2',
                 'pi@'+address,'cd / && sudo -n /usr/bin/python3 -'+(' --primary-route' if extended else '')],(ROOT/'node_health.py').read_text())
    try:
        r['node'] = json.loads(r['stdout']) if r['rc'] == 0 else None
    except ValueError:
        r['node'] = None
    return r


def sample(node_probe=None):
    node_probe = node_probe or node
    jobs = {
        'cluster_dns4': (dns, ('10.1.0.55',)),
        'cluster_dns6': (dns, ('fd36:5aa8:6971:1::55',)),
        'cluster_https4': (https, ('10.1.0.56','proxy.local.theama.co','/')),
        'cluster_https6': (https, ('fd36:5aa8:6971:1::56','proxy.local.theama.co','/')),
    }
    for label, (v4,v6,name,_) in NODES.items():
        jobs[label] = (node_probe,(v4,))
        for family,address in ((4,v4),(6,v6)):
            jobs[f'{label}_dns{family}'] = (dns,(address,))
            jobs[f'{label}_https{family}'] = (https,(address,name))
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {k:pool.submit(fn,*args) for k,(fn,args) in jobs.items()}
        result = {k:f.result() for k,f in futures.items()}
    return {'start':start,'end':time.monotonic(),'checks':result}


def role(n):
    return n.get('transition',{}).get('MESSAGE','').split('Syncing instances to ')[-1].split(' ')[0]


def evaluate(samples, phase=None, baseline=None):
    """Historical failures latch; transient standby failure is allowed after apply marker."""
    if not samples:
        return {'fatal':None,'healthy':False,'stable':False}
    base = (baseline or samples[0])['checks']
    stable_since = None
    failure = None
    last = None
    for s in samples:
        c = s['checks']
        if last is not None and s['start']-last > 8:
            failure = 'sampling_gap'
        last = s['start']
        if s['end']-s['start'] > 5:
            failure = 'probe_budget_exceeded'
        healthy = True
        for key,value in c.items():
            if key in NODES:
                n = value.get('node')
                baseline = base[key].get('node')
                if not n or not baseline:
                    healthy = False
                    if key == 'primary' or phase is None or s['start'] < phase:
                        failure = key+'_evidence_unavailable'
                    continue
                if n['boot'] != baseline['boot'] or n['hostname'] != NODES[key][3]:
                    failure = key+'_identity_changed'
                owned = set(n['addresses']) & VIPS
                if owned != (VIPS if key == 'primary' else set()):
                    failure = key+'_vip_ownership_changed'
                ok = role(n) == ('MASTER' if key == 'primary' else 'BACKUP') and n['services'] == ['active']*4
                if key == 'primary' and not ok:
                    failure = 'primary_health_failed'
                if key == 'primary' and n['transition'].get('__MONOTONIC_TIMESTAMP') != baseline['transition'].get('__MONOTONIC_TIMESTAMP'):
                    failure = 'primary_ha_transition'
            else:
                ok = value['ok']
                if not key.startswith('standby_') and not ok:
                    failure = key+'_failed'
            healthy = healthy and ok
        if not healthy and (phase is None or s['start'] < phase):
            failure = 'baseline_unhealthy'
        if phase is not None and s['start'] >= phase:
            if not healthy:
                stable_since = None
                if s['end']-phase > 60:
                    failure = 'standby_recovery_deadline'
            elif stable_since is None:
                stable_since = s['end']
            # A new FAULT between samples invalidates the stable interval.
            transition = c['standby'].get('node',{} ) or {}
            marker = transition.get('transition',{}).get('__MONOTONIC_TIMESTAMP')
            if len(samples) and s is not samples[0] and marker != previous_transition:
                stable_since = s['end'] if healthy else None
            previous_transition = marker
        else:
            previous_transition = (c['standby'].get('node') or {}).get('transition',{}).get('__MONOTONIC_TIMESTAMP')
    return {'fatal':failure,'healthy':healthy,'stable':stable_since is not None and samples[-1]['end']-stable_since >= 60}


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value))
    os.replace(tmp,path)


class Monitor:
    def __init__(self, root, probe=sample, evaluator=None):
        self.root,self.probe = root,probe
        self.evaluator = evaluator
        self.stop = threading.Event()
        self.samples = []
        self.thread = threading.Thread(target=self.run,daemon=True)
    def run(self):
        try:
            while not self.stop.is_set():
                s = self.probe()
                self.samples.append(s)
                with (self.root/'health-history.jsonl').open('a') as f:
                    f.write(json.dumps(s)+'\n')
                marker = self.root/'apply-marker.json'
                phase = json.loads(marker.read_text())['start'] if marker.exists() else None
                value = self.evaluator(self.samples,self.root) if self.evaluator else evaluate(self.samples,phase)
                value['end'] = s['end']
                atomic(self.root/'health-status.json',value)
                self.stop.wait(max(0,5-(time.monotonic()-s['start'])))
        except Exception as exc:
            atomic(self.root/'health-status.json',{'fatal':type(exc).__name__,'end':time.monotonic()})
    def start(self):
        self.thread.start()
    def close(self):
        self.stop.set();self.thread.join(timeout=6)


def gate(root, mode, timeout=130):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        p = root/'health-status.json'
        if p.exists():
            s = json.loads(p.read_text())
            if s.get('fatal') or time.monotonic()-s['end'] > 8:
                raise RuntimeError('cluster health gate failed: '+str(s.get('fatal') or 'stale_evidence'))
            after_apply = root/'applied-marker.json'
            elapsed = (s['end']-json.loads(after_apply.read_text())['start']) if after_apply.exists() else -1
            if s.get('stable' if mode == 'stable' else 'healthy') and (mode != 'stable' or elapsed >= 60):
                return
        time.sleep(.5)
    raise RuntimeError('health gate timed out')


if __name__ == '__main__':
    root = Path(sys.argv[1]);mode = sys.argv[2]
    if mode == 'applied':
        atomic(root/'applied-marker.json', {'start':time.monotonic()})
    elif mode == 'mark-recovery':
        atomic(root/'recovery-marker.json', {'start':time.monotonic()})
    elif mode == 'recovered':
        phase = json.loads((root/'recovery-marker.json').read_text())['start']
        deadline = time.monotonic()+130
        while time.monotonic() < deadline:
            # Read only complete append-only lines; the last writer may be active.
            raw = (root/'health-history.jsonl').read_text()
            lines = raw.splitlines() if raw.endswith('\n') else raw.splitlines()[:-1]
            samples = [json.loads(line) for line in lines]
            fresh = [s for s in samples if s['start'] >= phase]
            if fresh:
                value = evaluate(fresh, phase, baseline=samples[0])
                # Recovery cannot accept a reboot relative to pre-operation evidence.
                boots_match = all((fresh[-1]['checks'][n].get('node') or {}).get('boot') ==
                                  (samples[0]['checks'][n].get('node') or {}).get('boot') for n in NODES)
                if value['stable'] and not value['fatal'] and boots_match and time.monotonic()-fresh[-1]['end'] <= 8:
                    atomic(root/'recovery-result.json', {'recovered':True,'end':fresh[-1]['end']})
                    break
            time.sleep(.5)
        else:
            raise RuntimeError('rollback health recovery unproven; manual review required')
    elif mode == 'mark':
        gate(root,'healthy',timeout=10)
        atomic(root/'apply-marker.json',{'start':time.monotonic()})
    else:
        gate(root,mode)
