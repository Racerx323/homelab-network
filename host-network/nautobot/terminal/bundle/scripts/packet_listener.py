#!/usr/bin/env python3
"""Fixed-address test-only responder. No request body, commands or credentials."""
import json
import selectors
import socket
import sys
import time

ADDRESSES = ['10.1.2.170', 'fd36:5aa8:6971:1::170', '127.0.0.1']


def serve(nonce, addresses=ADDRESSES, port=8080, lifetime=170, maximum=64):
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('invalid nonce')
    sockets = []
    with selectors.DefaultSelector() as selector:
        try:
            for address in addresses:
                family = socket.AF_INET6 if ':' in address else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_STREAM)
                sockets.append(sock)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, port))
                sock.listen(8)
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ)
            deadline = time.monotonic() + lifetime
            count = 0
            print(json.dumps({'ready': True, 'addresses': addresses, 'port': port}), flush=True)
            while count < maximum and time.monotonic() < deadline:
                for key, _ in selector.select(min(1, max(0, deadline-time.monotonic()))):
                    conn, peer = key.fileobj.accept()
                    with conn:
                        conn.settimeout(1)
                        payload = {'nonce': nonce, 'peer': peer[0], 'local': conn.getsockname()[0]}
                        try:
                            conn.sendall((json.dumps(payload)+'\n').encode())
                        except OSError:
                            pass
                    count += 1
        finally:
            for sock in sockets:
                sock.close()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('nonce required')
    serve(sys.argv[1])
