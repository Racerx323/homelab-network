#!/usr/bin/env python3
"""Primary maintenance state and watchdog, sharing the qualified route transaction."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import proxy_route as route
from network_policy import load_policy

BASE=Path('/var/lib/nautobot-primary-route')
UUID='178f6c60-c62a-3c6c-9fae-04ebf2c4fdc3'
TIMER='nautobot-primary-route-rollback.timer'
PROFILE='/etc/NetworkManager/system-connections/Wired connection 1.nmconnection'
PROFILE_HASH='e7aee5e0b6bd7cbbdc7a2d01dc21367f3b9723369c02cefb90672d5e0c03cdd2'
HA_HASH='de67123685edb21cdfaee95eb0497d9ab527c546cf730a5f51506bc293eab92a'


def save(root, state):
    tmp=root/'state.tmp';tmp.write_text(json.dumps(state));tmp.chmod(0o600)
    with tmp.open('rb') as f:os.fsync(f.fileno())
    os.replace(tmp,root/'state.json')


def dispatch(action, root=BASE, call=route.run, transact=None, snapshot=route.profile_snapshot):
    if transact is None:
        transact=lambda a:route.transaction(a,load_policy(Path('/etc/nautobot-proxy-route/policy.json')),'pihole0',UUID,primary=True)
    if call(['hostname','-s'])!='j1-svpihole0':raise RuntimeError('wrong host')
    state_path=root/'state.json'
    if action=='prepare':
        if state_path.exists() or (route.BASE/'state.json').exists():raise RuntimeError('existing primary state')
        if call(['nmcli','--version'])!='nmcli tool, version 1.42.4':raise RuntimeError('manager drift')
        if call(['nmcli','-g','GENERAL.CON-UUID','device','show','eth0'])!=UUID:raise RuntimeError('profile drift')
        routes=json.loads(call(['ip','-6','-j','route','show','table','all']))
        if any(x.get('dst','').split('/')[0]=='fd36:5aa8:6971:1::170' for x in routes):raise RuntimeError('conflicting destination route')
        snap=snapshot(PROFILE)
        if snap['sha256']!=PROFILE_HASH:raise RuntimeError('profile hash drift')
        if hashlib.sha256(Path('/etc/keepalived/keepalived.conf').read_bytes()).hexdigest()!=HA_HASH:raise RuntimeError('HA config drift')
        if call(['systemctl','is-active','keepalived'])!='active':raise RuntimeError('baseline service inactive')
        cursor=call(['journalctl','-n','0','--show-cursor','--no-pager']).split('-- cursor: ')[-1].strip()
        if not cursor:raise RuntimeError('missing journal cursor')
        save(root,{'status':'prepared','boot':call(['cat','/proc/sys/kernel/random/boot_id']), 'profile':snap, 'journal_cursor':cursor})
        return
    s=json.loads(state_path.read_text())
    if action=='report':
        journal=call(['journalctl','--after-cursor',s['journal_cursor'],'-u','keepalived','-u','NetworkManager','--no-pager','-n','200'])
        print(json.dumps({'status':s['status'],'boot_matches':s['boot']==call(['cat','/proc/sys/kernel/random/boot_id']),
                          'recovery_errors':s.get('recovery_errors',[]),'journal_tail':journal[-10000:],
                          'journal_truncated':len(journal)>10000}));return
    if action=='expire' and s['status'] in {'accepted','rolled_back'}:return
    if action in {'rollback','expire'}:
        # Service restoration is independent of route rollback success.
        errors=[]
        if (route.BASE/'state.json').exists():
            try:transact('rollback')
            except Exception as e:errors.append('route:'+type(e).__name__)
        try:
            call(['systemctl','start','keepalived'])
            if call(['systemctl','is-active','keepalived'])!='active':raise RuntimeError('not active')
        except Exception as e:errors.append('service:'+type(e).__name__)
        s['status']='recovery_failed' if errors else 'rolled_back';s['recovery_errors']=errors;save(root,s)
        if errors:raise RuntimeError('manual recovery required: '+','.join(errors))
        return
    if s['boot']!=call(['cat','/proc/sys/kernel/random/boot_id']):raise RuntimeError('boot changed')
    required={'handoff':'prepared','apply':'handoff','failback':'route_applied','accept':'failback'}
    if action not in required or s['status']!=required[action]:raise RuntimeError('invalid primary phase')
    if action=='handoff':
        s['status']='handoff';save(root,s)  # Persist before stopping; expiry restores service.
        call(['systemctl','stop','keepalived'])
    elif action=='apply':
        if call(['systemctl','show','keepalived','-p','ActiveState','--value'])!='inactive':raise RuntimeError('handoff not complete')
        if snapshot(PROFILE)['sha256']!=s['profile']['sha256']:raise RuntimeError('profile changed during handoff')
        transact('apply');s['status']='route_applied';save(root,s)
    elif action=='failback':
        s['status']='failback';save(root,s)
        call(['systemctl','start','keepalived'])
    elif action=='accept':
        if call(['systemctl','is-active','keepalived'])!='active':raise RuntimeError('service not restored')
        transact('accept');s['status']='accepted';save(root,s)
        call(['systemctl','stop',TIMER])


if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('root required')
    os.umask(0o077)
    for p in (BASE,route.BASE):
        p.mkdir(mode=0o700,exist_ok=True)
        if p.is_symlink() or p.stat().st_uid!=0 or p.stat().st_mode & 0o077:raise SystemExit('unsafe state directory')
    with (BASE/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        dispatch(sys.argv[1])
