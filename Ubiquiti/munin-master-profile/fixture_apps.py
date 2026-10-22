"""Synthetic HTTP redirect, verified HTTPS assets and SMTP in isolated tests only."""
import base64
import http.server
import socket
import socketserver
import ssl
import threading


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.server.server_port == 80:
            self.send_response(301)
            self.send_header('Location', 'https://munin.local.theama.co/')
            self.end_headers()
            return
        if self.path.endswith('.png'):
            kind = 'image/png'
            body = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9mQAAAAASUVORK5CYII=')
        elif self.path.endswith('.css'):
            kind, body = 'text/css', b'body { color: black; }\n'
        else:
            kind, body = 'text/html', b'<html>fixture healthy</html>\n'
        self.send_response(200); self.send_header('Content-Type', kind)
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args):
        pass


class IPv6HTTP(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'220 fixture SMTP\r\n'); self.wfile.flush()
        if self.rfile.readline(512) == b'QUIT\r\n':
            self.wfile.write(b'221 bye\r\n')


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == '__main__':
    servers = [IPv6HTTP(('::', port), HTTP) for port in (80, 8000)]
    https = IPv6HTTP(('::', 443), HTTP)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/fixture-tls/server.crt', '/fixture-tls/server.key')
    https.socket = context.wrap_socket(https.socket, server_side=True)
    servers.append(https)
    servers.append(SMTPServer(('127.0.0.1', 8025), SMTP))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()
