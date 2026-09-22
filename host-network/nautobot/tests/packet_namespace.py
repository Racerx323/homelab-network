#!/usr/bin/env python3
"""Run ONLY in a disposable user+network namespace; no production hosts."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from network_policy import load_policy, nft_rules, normalized_table, digest


def run(*args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=True, timeout=10).stdout


def main():
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise RuntimeError('refusing host network namespace')
    run('ip', 'link', 'set', 'lo', 'up')
    child = subprocess.Popen(['unshare', '--net', 'sleep', '120'])
    sockets = []
    try:
        for _ in range(100):
            if os.readlink(f'/proc/{child.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                break
            time.sleep(.01)
        else:
            raise RuntimeError('child namespace missing')
        ns = ['nsenter', '-t', str(child.pid), '-n']
        run('ip', 'link', 'add', 'guard0', 'type', 'veth', 'peer', 'name', 'client0')
        run('ip', 'link', 'set', 'client0', 'netns', str(child.pid))
        run('ip', 'link', 'set', 'guard0', 'up')
        run(*ns, 'ip', 'link', 'set', 'lo', 'up')
        run(*ns, 'ip', 'link', 'set', 'client0', 'up')
        for addr in ['10.1.2.170/22', 'fd36:5aa8:6971:1::170/64']:
            run('ip', 'address', 'add', addr, 'dev', 'guard0', *(['nodad'] if ':' in addr else []))
        for addr in ['10.1.0.53/22', '10.1.0.54/22', '10.1.3.83/22',
                     'fd36:5aa8:6971:1::53/64', 'fd36:5aa8:6971:1::54/64',
                     'fd36:5aa8:6971:1::56/64', 'fd36:5aa8:6971:1::83/64']:
            run(*ns, 'ip', 'address', 'add', addr, 'dev', 'client0', *(['nodad'] if ':' in addr else []))
        rules = nft_rules(load_policy())
        run('/usr/sbin/nft', '--check', '-f', '-', data=rules)
        run('/usr/sbin/nft', '-f', '-', data=rules)
        table = json.loads(run('/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'nautobot_backend'))
        def serve(s):
            while True:
                try:
                    c, _ = s.accept()
                    c.sendall(b'guard-test\n')
                    c.close()
                except OSError:
                    return
        for family, addr in [(socket.AF_INET, '10.1.2.170'), (socket.AF_INET6, 'fd36:5aa8:6971:1::170')]:
            for port in [8080, 22, 4949, 10000]:
                s = socket.socket(family)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((addr, port)); s.listen(); sockets.append(s)
                threading.Thread(target=serve, args=(s,), daemon=True).start()
        def probe(src, port):
            dst = 'fd36:5aa8:6971:1::170' if ':' in src else '10.1.2.170'
            code = '''import socket,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)
s.settimeout(.4);s.bind((sys.argv[1],0))
try:
 s.connect((sys.argv[2],int(sys.argv[3]))); assert s.recv(40)==b'guard-test\\n'; print('allowed')
except socket.timeout: print('dropped')
'''
            return run(*ns, sys.executable, '-c', code, src, dst, str(port)).strip()
        results = {}
        for src in ['10.1.0.53','10.1.0.54','fd36:5aa8:6971:1::53','fd36:5aa8:6971:1::54']:
            results[src] = probe(src, 8080)
            assert results[src] == 'allowed', results
        for src in ['10.1.3.83','fd36:5aa8:6971:1::83','fd36:5aa8:6971:1::56']:
            results[src] = probe(src, 8080)
            assert results[src] == 'dropped', results
            for port in [22,4949,10000]:
                assert probe(src,port) == 'allowed'
        after = json.loads(run('/usr/sbin/nft','-j','list','table','inet','nautobot_backend'))
        assert normalized_table(after) == normalized_table(table)
        counters = {x['rule']['comment']: next(e['counter']['packets'] for e in x['rule']['expr'] if 'counter' in e)
                    for x in after['nftables'] if 'rule' in x and 'comment' in x['rule']}
        assert counters['deny-v4'] > 0 and counters['deny-v6'] > 0
        # Delete only owned table and demonstrate recovery of previously denied path.
        run('/usr/sbin/nft','delete','table','inet','nautobot_backend')
        assert probe('10.1.3.83',8080) == 'allowed'
        assert probe('fd36:5aa8:6971:1::83',8080) == 'allowed'
        print(json.dumps({'passed':True,'sources':results,'counters':counters,
                          'local_table_digest':digest(normalized_table(table)),
                          'qualification':'local kernel only; target version readback still required'}))
    finally:
        for s in sockets:s.close()
        child.terminate();child.wait(timeout=5)


if __name__ == '__main__':
    main()
