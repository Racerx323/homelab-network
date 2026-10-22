"""Run retained, isolated Podman network-wrapper fixtures; never run setup on a host."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parent
MODES = ('commit', 'controller-loss', 'worker-loss', 'failed-health', 'foreign-drift', 'after-write-failure', 'missing-aaaa')
INPUTS = ('deploy.py', 'guard.py', 'static-settings.json', 'qualify_dashboard.py',
          'fixture_apps.py', 'test_native_deploy.py', 'test_native_rollback.py', 'run_native_https.py')


def hashes():
    return {n: hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in INPUTS}


def run_case(mode, args):
    label = mode+'-'+args.revision
    directory = args.evidence/label
    directory.mkdir(mode=0o700)
    name = 'svmf-network-https-'+label
    argv = ['podman', 'run', '-d', '--name', name, '--network', 'none', '--systemd', 'always',
            '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--cap-add', 'SYS_ADMIN',
            '--security-opt', 'unmask=/proc/sys', '-v', str(ROOT)+':/candidate:ro',
            '-v', str(directory)+':/evidence:rw', args.image]
    original = hashes()
    (directory/'launch.json').write_text(json.dumps({'argv': argv, 'source_sha256': original,
                                                   'image': args.image, 'epoch': time.time()})+'\n')
    result = None
    created = False
    try:
        with (directory/'launch.log').open('xb') as log:
            subprocess.run(argv, stdout=log, stderr=log, check=True)
        created = True
        subprocess.run(['podman', 'exec', name, 'systemctl', 'is-system-running', '--wait'],
                       capture_output=True, timeout=40)
        test = ['podman', 'exec', name, 'python3', '-I', '-B', '/candidate/test_native_deploy.py', mode]
        (directory/'test-invocation.json').write_text(json.dumps({'argv': test, 'log': 'test.log'})+'\n')
        with (directory/'test.log').open('xb') as log:
            result = subprocess.run(test, stdout=log, stderr=log, timeout=350)
        (directory/'test.exit').write_text(str(result.returncode)+'\n')
    except Exception as error:
        (directory/'outer-error.json').write_text(json.dumps({'type': type(error).__name__})+'\n')
    finally:
        if created:
            subprocess.run(['podman', 'cp', name+':/var/lib/svmf-network/svmf-network-fixture-'+mode+'/state.json',
                            str(directory/'target-state.json')], capture_output=True)
            with (directory/'journal.log').open('xb') as log:
                subprocess.run(['podman', 'exec', name, 'journalctl', '--no-pager', '-u', 'NetworkManager.service',
                                '-u', 'ssh.service', '-u', 'svmf-fixture-app.service',
                                '-u', 'svmf-network-fixture-'+mode+'.service'], stdout=log, stderr=log)
            with (directory/'stop.log').open('xb') as log:
                subprocess.run(['podman', 'stop', '--time', '10', name], stdout=log, stderr=log, check=True)
        terminal = {'exit': result.returncode if result else None, 'stopped': created,
                    'source_unchanged': hashes() == original, 'epoch': time.time()}
        (directory/'terminal.json').write_text(json.dumps(terminal)+'\n')
    print(json.dumps({'case': label, **terminal}), flush=True)
    return terminal['exit'] == 0 and terminal['source_unchanged']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--jobs', type=int, choices=(1, 2), default=1)
    parser.add_argument('modes', nargs='+', choices=MODES)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}', args.image) or not re.fullmatch(r'r[0-9]{1,3}', args.revision):
        raise ValueError('immutable image ID and bounded revision required')
    args.evidence = args.evidence.resolve(strict=True)
    os.umask(0o077)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        outcomes = list(pool.map(lambda mode: run_case(mode, args), args.modes))
    raise SystemExit(0 if all(outcomes) else 1)


if __name__ == '__main__':
    main()
