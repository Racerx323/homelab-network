#!/usr/bin/env python3
"""Thin guard-specific Ansible invocation and bounded independent readback."""
import json
import subprocess
import sys
from pathlib import Path
from guard_health import check, SSH


def execute(root, env, approved):
    accepted = False
    result = {'bundle': approved, 'accepted': False, 'returncode': None,
              'scope': 'guard_installation_only', 'error': None}
    try:
        before = check()
        (root / 'health-before.json').write_text(json.dumps(before))
        if not all(before.values()):
            raise RuntimeError('management baseline failed; no target mutation attempted')
        cmd = ['ansible-playbook', '-i', '10.1.2.170,', '-u', 'ama', 'ansible/guard.yaml',
               '--extra-vars', json.dumps({'candidate_execution_enabled': True,
                                          'controller_evidence': str(root)})]
        with (root / 'stdout.log').open('w') as out, (root / 'stderr.log').open('w') as err:
            run = subprocess.run(cmd, cwd=root, env=env, stdout=out, stderr=err, timeout=240)
        result['returncode'] = run.returncode
        report = subprocess.run(SSH + ['ama@10.1.2.170',
            'cd / && sudo -n /usr/bin/python3 -I /var/lib/nautobot-backend-install/install_state.py report'],
            capture_output=True, text=True, timeout=30)
        (root / 'node-report.json').write_text(report.stdout[:10000])
        (root / 'node-report.stderr').write_text(report.stderr[:2000])
        result['node_report_rc'] = report.returncode
        if report.returncode == 0:
            state = json.loads(report.stdout)
            result['node_status'] = state.get('status')
            accepted = run.returncode == 0 and state.get('status') == 'accepted' and state.get('boot_matches') is True
        after = check()
        (root / 'health-final.json').write_text(json.dumps(after))
        accepted = accepted and all(after.values())
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)[:400]
        accepted = False
    result['accepted'] = accepted
    result['recovery_note'] = 'On timeout/disconnect retain the 300-second node watchdog; collect its terminal state before retry. Never rerun first install.'
    (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Protected evidence: ' + str(root))
    return 0 if accepted else 1
