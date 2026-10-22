"""Independent post-terminal readback of a retained isolated rollback fixture."""
import json
import os
from pathlib import Path
import subprocess
import time


def command(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if p.returncode:
        raise RuntimeError('independent recovery probe failed')
    return p.stdout.strip()


def main():
    if os.geteuid() != 0 or not Path('/run/.containerenv').exists():
        raise RuntimeError('root fixture container required')
    evidence = Path('/evidence')
    result = json.loads((evidence/'result.json').read_text())
    if not result['passed'] or not result['saved_profile_restored']:
        raise RuntimeError('completed rollback fixture required')
    rows = [json.loads(line) for line in (evidence/'commands.jsonl').read_text().splitlines()]
    checkpoint = next(i for i, row in enumerate(rows) if 'CheckpointCreate' in row['argv'])
    previous = [r for r in rows[:checkpoint] if r['argv'] == ['ip', '-j', 'address', 'show', 'dev', 'nmtest0']][-1]
    before = json.loads(previous['stdout'])[0]['addr_info']
    identities = lambda addr: {(a['family'], a['local'], a['prefixlen']) for a in addr}
    if '10.1.3.83' not in {a['local'] for a in before}:
        raise RuntimeError('fixture did not establish complete original DHCP baseline')
    old_ula = next(a['local'] for a in before if a['local'].startswith('fd36:5aa8:6971:1:'))
    deadline = time.monotonic()+60
    while True:
        after = json.loads(command(['ip', '-j', 'address', 'show', 'dev', 'nmtest0']))[0]['addr_info']
        ready = identities(before) == identities(after) and all(not a.get('tentative') and not a.get('dadfailed') for a in after)
        if ready:
            route4 = json.loads(command(['ip', '-4', '-j', 'route', 'get', '10.1.0.51']))[0]
            route6 = json.loads(command(['ip', '-6', '-j', 'route', 'get', 'fd36:5aa8:6971:1::51']))[0]
            default6 = json.loads(command(['ip', '-6', '-j', 'route', 'show', 'default']))
            dns = command(['nmcli', '-g', 'IP4.DNS,IP6.DNS', 'device', 'show', 'nmtest0']).replace('\\:', ':')
            if (route4.get('prefsrc') == '10.1.3.83' and route6.get('prefsrc') == old_ula
                    and default6 and '10.1.0.55' in dns and 'fd36:5aa8:6971:1::55' in dns):
                break
        if time.monotonic() >= deadline:
            raise RuntimeError('original active addresses/routes/DNS did not converge in 60 seconds')
        time.sleep(1)
    for address in ('10.1.3.83', old_ula):
        command(['ip', 'netns', 'exec', 'nm-router', 'ping', '-c', '1', '-W', '2', address])
    (evidence/'recovery-readback.json').write_text(json.dumps({
        'original_active_addresses': True, 'original_route_sources': True,
        'ra_default_route': True, 'dns_restored': True, 'independent_peer4': True,
        'independent_peer6': True, 'production_acceptance': False}, indent=2)+'\n')


if __name__ == '__main__':
    main()
