#!/usr/bin/env python3
"""Bounded management and established IPv4 monitoring checks; no SMART queries."""
import json
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5']
MUNIN = '''import socket,json
with socket.create_connection(('10.1.2.170',4949),timeout=5) as s:
 s.settimeout(5); f=s.makefile('rb'); banner=f.readline(4096)
 s.sendall(b'fetch load\\n'); line=f.readline(4096); end=f.readline(4096)
 assert banner.startswith(b'# munin node') and line.startswith(b'load.value ') and end.strip()==b'.'
 s.sendall(b'quit\\n')
print('MUNIN_OK')
'''


def command(args, data=None):
    r = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15)
    if r.returncode:
        raise RuntimeError('health command failed')
    return r.stdout


def tcp(host, port):
    with socket.create_connection((host, port), timeout=5):
        return True


def check():
    tasks = [('ssh', lambda: command(SSH + ['ama@10.1.2.170', 'true']) == ''),
             ('munin_ipv4', lambda: command(SSH + ['pi@10.1.3.83', 'cd / && /usr/bin/python3 -'], MUNIN).strip() == 'MUNIN_OK')]
    for host, family in [('10.1.2.170', '4'), ('fd36:5aa8:6971:1::170', '6')]:
        for port in [22, 10000]:
            tasks.append((f'tcp{family}_{port}', lambda h=host, p=port: tcp(h, p)))
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [(name, pool.submit(fn)) for name, fn in tasks]
        results = {}
        for name, future in futures:
            try:
                results[name] = future.result() is True
            except Exception:
                results[name] = False
    return results


if __name__ == '__main__':
    result = check()
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if all(result.values()) else 1)
