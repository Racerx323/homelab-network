#!/usr/bin/env python3
"""Verify-bundle delegate: Ansible lifecycle and independent cleanup readback."""
import json
import secrets
import subprocess
from guard_health import check, SSH


def execute(root,env,approved):
    result={'bundle':approved,'accepted':False,'error':None}
    try:
        baseline=check();(root/'health-before.json').write_text(json.dumps(baseline))
        if not all(baseline.values()):raise RuntimeError('management baseline failed')
        nonce=secrets.token_hex(16)
        with (root/'stdout.log').open('w') as out,(root/'stderr.log').open('w') as err:
            run=subprocess.run(['ansible-playbook','-i','10.1.2.170,','-u','ama','ansible/packet.yaml','--extra-vars',
                json.dumps({'candidate_execution_enabled':True,'packet_nonce':nonce,'controller_evidence':str(root)})],
                cwd=root,env=env,stdout=out,stderr=err,timeout=240)
        result['returncode']=run.returncode
        readback=subprocess.run(SSH+['ama@10.1.2.170','cd / && sudo -n /usr/bin/python3 -I /var/lib/nautobot-packet-trial/packet_node.py snapshot'],
            capture_output=True,text=True,timeout=30)
        (root/'readback.json').write_text(readback.stdout[:16000]);(root/'readback.stderr').write_text(readback.stderr[:2000])
        state=json.loads(readback.stdout) if readback.returncode==0 else {}
        probes=json.loads((root/'packet-probes.json').read_text()) if (root/'packet-probes.json').exists() else {}
        health=check();(root/'health-final.json').write_text(json.dumps(health))
        result['accepted']=(run.returncode==0 and readback.returncode==0 and state.get('status')=='cleaned'
            and state.get('listeners')=='' and probes.get('passed') is True and all(health.values()))
    except Exception as exc:
        result['error']=type(exc).__name__+': '+str(exc)[:300]
    result['recovery_note']='Do not remove guard. Node listener expires within 180 seconds; independently verify closure and health before any retry.'
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Protected evidence: '+str(root))
    return 0 if result['accepted'] else 1
