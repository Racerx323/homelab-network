#!/usr/bin/env python3
"""Phase-aware gates sharing existing controller probes; no mutations on nodes."""
import json
from pathlib import Path
import sys
import time
import health_watch as h

HA_HASHES={'primary':'de67123685edb21cdfaee95eb0497d9ab527c546cf730a5f51506bc293eab92a','standby':'cb4749c6f9e1a247dc481809652470e5b35c5ea3992e87945bada9292f5cbd66'}
STANDBY_PROFILE='a9cca5985767526c3f84659c7fd04259d172dddca1df9676376b40953d1e58cf'
PHASES=['baseline','handoff','apply','settled','failback','final']


def evaluate(samples, markers, baseline_sample=None):
    if not samples:return {'fatal':None,'healthy':False,'stable':False}
    fatal=None;stable_since=None;last=None;previous_phase=None
    baseline=(baseline_sample or samples[0])['checks']
    for s in samples:
        phase='baseline';start=samples[0]['start']
        for m in markers:
            if m['start']<=s['start']:phase,start=m['phase'],m['start']
        if phase!=previous_phase:stable_since=None
        previous_phase=phase
        elapsed=s['end']-start;c=s['checks']
        if (last is not None and s['start']-last>8) or s['end']-s['start']>5:fatal='sampling_gap'
        last=s['start'];healthy=True
        # Ten seconds for expected ARP/ND/VRRP handover only, never during apply.
        transition=phase in {'handoff','failback','recovery'} and elapsed<=10
        for k,v in c.items():
            if k in h.NODES:continue
            if not v['ok']:
                healthy=False
                allowed=(transition and k.startswith('cluster_')) or (phase=='apply' and elapsed<=60 and k.startswith('primary_'))
                if not allowed:fatal=k+'_failed'
        for key in h.NODES:
            n=c[key].get('node');base=baseline[key].get('node')
            if not n or not base:
                healthy=False
                if not (key=='primary' and phase=='apply' and elapsed<=60):fatal=key+'_unavailable'
                continue
            if n.get('ha_sha256')!=HA_HASHES[key]:fatal=key+'_ha_config_drift'
            if key=='standby' and n.get('profile_sha256')!=STANDBY_PROFILE:fatal='standby_profile_drift'
            if n['boot']!=base['boot'] or n['hostname']!=h.NODES[key][3]:fatal='node_identity_changed'
            desired_owner='standby' if phase in {'handoff','apply','settled'} else 'primary'
            owned=set(n['addresses']) & h.VIPS
            ownership_ok=owned==(h.VIPS if key==desired_owner else set())
            # Permit the configured preemption interval, but require complete ownership
            # and health within 60 seconds; missing/both-owner evidence never passes.
            role_transition=phase in {'handoff','failback','recovery'} and elapsed<=60
            stopped=key=='primary' and phase in {'handoff','apply','settled'}
            services=['active','inactive','active','active'] if stopped else ['active']*4
            role_ok=stopped or h.role(n)==('MASTER' if key==desired_owner else 'BACKUP')
            ok=ownership_ok and role_ok and n['services']==services
            if not ok:
                healthy=False
                if not role_transition and not (key=='primary' and phase=='apply' and elapsed<=60):fatal=key+'_role_or_service_failed'
            if key=='standby' and n.get('source')!='fd36:5aa8:6971:1::54':fatal='standby_source_drift'
            if key=='primary' and phase in {'settled','failback','final'} and n.get('source')!='fd36:5aa8:6971:1::53':fatal='primary_source_mismatch'
        if healthy:
            if stable_since is None:stable_since=s['end']
        else:stable_since=None
    return {'fatal':fatal,'healthy':healthy,'stable':stable_since is not None and s['end']-stable_since>=60,
            'phase':phase,'end':s['end']}


def markers(root):
    p=root/'primary-markers.json'
    return json.loads(p.read_text()) if p.exists() else []


def from_root(samples,root):
    return evaluate(samples,markers(root))


def gate(root,mode,timeout=140):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        p=root/'health-status.json'
        if p.exists():
            v=json.loads(p.read_text())
            if v.get('fatal') or time.monotonic()-v['end']>8:raise RuntimeError('primary health gate: '+str(v.get('fatal') or 'stale'))
            phase=(markers(root) or [{'phase':'baseline'}])[-1]['phase']
            if v.get('phase')==phase and v.get('stable' if mode=='stable' else 'healthy'):return
        time.sleep(.5)
    raise RuntimeError('primary health deadline')


def mark(root,phase):
    prior=markers(root)
    expected=PHASES[len(prior)+1] if len(prior)+1<len(PHASES) else None
    if phase!=expected:raise RuntimeError('invalid phase progression')
    gate(root,'healthy',70)
    prior.append({'phase':phase,'start':time.monotonic()})
    h.atomic(root/'primary-markers.json',prior)


if __name__=='__main__':
    root=Path(sys.argv[1]);action=sys.argv[2]
    if action in PHASES[1:]:mark(root,action)
    elif action=='recovered':
        # Preserve failure history. Separately verify original role restoration.
        start=time.monotonic();deadline=start+140
        while time.monotonic()<deadline:
            raw=(root/'health-history.jsonl').read_text()
            rows=[json.loads(l) for l in raw.splitlines()[:-1 if not raw.endswith('\n') else None]]
            fresh=[s for s in rows if s['start']>=start]
            if fresh:
                v=evaluate(fresh,[{'phase':'recovery','start':start}],baseline_sample=rows[0])
                same_boot=all((fresh[-1]['checks'][n].get('node') or {}).get('boot')==rows[0]['checks'][n]['node']['boot'] for n in h.NODES)
                if v['stable'] and not v['fatal'] and same_boot and time.monotonic()-v['end']<=8:
                    h.atomic(root/'recovery-result.json',{'recovered':True,'end':v['end']});break
            time.sleep(.5)
        else:raise RuntimeError('primary recovery unproven')
    else:gate(root,action)
