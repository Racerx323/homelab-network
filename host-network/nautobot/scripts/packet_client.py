#!/usr/bin/env python3
"""One bounded unbound TCP probe, no retry or source binding."""
import json
import socket
import sys
import time


def probe(address, port=8080):
    started = time.monotonic()
    result = {'destination': address, 'outcome': 'error', 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        try:
            s.connect((address, port))
            result['source'] = s.getsockname()[0]
            data = b''
            while b'\n' not in data and len(data) < 1024:
                chunk = s.recv(1024-len(data))
                if not chunk:
                    break
                data += chunk
            result['response'] = json.loads(data)
            result['outcome'] = 'response'
        except socket.timeout:
            result['outcome'] = 'timeout'
        except (OSError, ValueError) as exc:
            result['error'] = type(exc).__name__
        result['source'] = s.getsockname()[0]
    result['elapsed'] = time.monotonic()-started
    return result


if __name__ == '__main__':
    print(json.dumps(probe(sys.argv[1])))
