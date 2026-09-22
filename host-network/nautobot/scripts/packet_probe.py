#!/usr/bin/env python3
"""Controller trial: bounded probes, paired counters, retained SSH tunnel."""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from guard_health import SSH, check
from packet_client import probe

TARGET='ama@10.1.2.170'
DESTS=['10.1.2.170','fd36:5aa8:6971:1::170']
SOURCES={'10.1.0.53':['10.1.0.53','fd36:5aa8:6971:1::53'],
         '10.1.0.54':['10.1.0.54','fd36:5aa8:6971:1::54']}


def command(args, data=None):
    r=subprocess.run(args,input=data,text=True,capture_output=True,timeout=12)
    if r.returncode:
        raise RuntimeError('probe command failed')
    return r.stdout


def snapshot():
    return json.loads(command(SSH+[TARGET,'cd / && sudo -n /usr/bin/python3 -I /var/lib/nautobot-packet-trial/packet_node.py snapshot']))


def allowed(value, nonce, source, destination):
    return (value.get('outcome')=='response' and value.get('source')==source and
            value.get('response')=={'nonce':nonce,'peer':source,'local':destination})


def denied(value, before, after, family, expected_source):
    key='deny-v'+str(family)
    other='deny-v'+('6' if family==4 else '4')
    return (value.get('outcome')=='timeout' and value.get('source')==expected_source and
            value.get('response') is None and after[key]>before[key] and
            after[other]==before[other])


def trial(root, nonce):
    results={};tunnel=None
    code=(root/'scripts/packet_client.py').read_text()
    def client(host,destination):
        return json.loads(command(SSH+['pi@'+host,'cd / && /usr/bin/python3 - '+destination],code))
    try:
        # Reserve then release an ephemeral loopback port; SSH refuses any race.
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        tunnel=subprocess.Popen(SSH+['-N','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=5',
            '-o','ServerAliveCountMax=2','-L',f'127.0.0.1:{port}:127.0.0.1:8080',TARGET],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(20):
            if tunnel.poll() is not None:raise RuntimeError('tunnel exited')
            loop=probe('127.0.0.1',port)
            if allowed(loop,nonce,'127.0.0.1','127.0.0.1'):break
            time.sleep(.1)
        else:raise RuntimeError('loopback unavailable')
        results['loopback_before']=loop
        for host,sources in SOURCES.items():
            route_code = "import subprocess,json;u=subprocess.check_output(['id','-u','caddy'],text=True).strip();print(subprocess.check_output(['ip','-6','-j','route','get','fd36:5aa8:6971:1::170','uid',u],text=True))"
            route=json.loads(command(SSH+['pi@'+host,'cd / && /usr/bin/python3 -'],route_code))
            results[host+':caddy_uid_route']=route
            if route[0].get('prefsrc')!=sources[1]:raise RuntimeError('Caddy UID source drift')
            for i,destination in enumerate(DESTS):
                value=client(host,destination);results[host+':'+destination]=value
                if not allowed(value,nonce,sources[i],destination):raise RuntimeError('allowed source failed')
        # Fresh unbound source choice for denied client; not a configured guess.
        expected={}
        for i,destination in enumerate(DESTS):
            route=json.loads(command(SSH+['pi@10.1.3.83',f'ip -{"6" if i else "4"} -j route get {destination}']))
            expected[i]=route[0]['prefsrc']
        for i,destination in enumerate(DESTS):
            before_allowed=client('10.1.0.53',destination)
            if not allowed(before_allowed,nonce,SOURCES['10.1.0.53'][i],destination):raise RuntimeError('bracket before failed')
            before_state=snapshot();before=before_state['counters'];value=client('10.1.3.83',destination);after_state=snapshot();after=after_state['counters']
            after_allowed=client('10.1.0.53',destination)
            results['deny'+str(i)]={'probe':value,'before':before_state,'after':after_state,'bracket_before':before_allowed,'bracket_after':after_allowed}
            if not denied(value,before,after,6 if i else 4,expected[i]):raise RuntimeError('denial unproven')
            if not allowed(after_allowed,nonce,SOURCES['10.1.0.53'][i],destination):raise RuntimeError('bracket after failed')
        results['health']=check()
        if not all(results['health'].values()):raise RuntimeError('health failed')
        results['loopback_after']=probe('127.0.0.1',port)
        if tunnel.poll() is not None or not allowed(results['loopback_after'],nonce,'127.0.0.1','127.0.0.1'):
            raise RuntimeError('retained tunnel failed')
        results['passed']=True
    except Exception as exc:
        results['passed']=False;results['error']=type(exc).__name__+': '+str(exc)[:200]
    finally:
        if tunnel is not None:
            tunnel.terminate()
            try:tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:tunnel.kill();tunnel.wait(timeout=5)
            results['tunnel_stopped']=tunnel.poll() is not None
            with socket.socket() as s:
                s.settimeout(1);results['tunnel_port_closed']=s.connect_ex(('127.0.0.1',port))!=0
        results['passed']=results.get('passed',False) and results.get('tunnel_stopped',False) and results.get('tunnel_port_closed',False)
        (root/'packet-probes.json').write_text(json.dumps(results,indent=2)+'\n')
    return results['passed']


if __name__=='__main__':
    sys.exit(0 if trial(Path(sys.argv[1]),sys.argv[2]) else 1)
