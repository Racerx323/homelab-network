"""Offline qualification boundaries: verified TLS, discovery, archives and read-only capture."""
import importlib.util
import io
import json
from pathlib import Path
import ssl
import tarfile
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent


def load(name):
    loader = importlib.util.spec_from_file_location(name, ROOT/(name+'.py'))
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    return module


q, a = load('qualify_dashboard'), load('inspect_apache')


class QualificationTests(unittest.TestCase):
    def test_link_discovery_has_no_external_query_fragment_or_non_get_paths(self):
        links = q.Links('/')
        links.feed('''<a href="/host/index.html">host</a><link href="/static/style.css">
            <img src="/host/cpu-day.png"><a href="https://evil.invalid/x.html">external</a>
            <img src="/x-day.png?secret=value"><a href="/private.cgi">cgi</a>
            <a href="//evil.invalid/a.html">other</a><a href="/x.html#secret">fragment</a>
            <img src="/host/cpu-year.png">''')
        self.assertEqual(links.links, [('page', '/host/index.html'), ('asset', '/static/style.css'), ('graph', '/host/cpu-day.png')])

    def test_direct_connect_keeps_sni_and_family_without_dns(self):
        for address, family in zip(q.ADDRESSES, (q.socket.AF_INET, q.socket.AF_INET6)):
            with self.subTest(address=address), patch.object(q.socket, 'socket') as sock:
                context = ssl.create_default_context()
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                with patch.object(context, 'wrap_socket') as wrap:
                    q.LiteralHTTPS(address, context).connect()
                    sock.assert_called_once_with(family, q.socket.SOCK_STREAM)
                    sock.return_value.connect.assert_called_once_with((address, 443))
                    wrap.assert_called_once_with(sock.return_value, server_hostname=q.HOST)

    def test_request_keeps_host_verification_metadata_and_discards_body_and_cookies(self):
        with patch.object(q, 'LiteralHTTPS') as connection:
            client = connection.return_value
            client.sock.getsockname.return_value = ('10.1.0.2', 1234)
            client.sock.version.return_value = 'TLSv1.3'
            client.sock.getpeercert.side_effect = [b'public-cert', {'subjectAltName': [('DNS', q.HOST)]}]
            response = client.getresponse.return_value
            response.status = 200
            response.getheader.side_effect = lambda key: {'Content-Type': 'text/html', 'Set-Cookie': 'secret'}.get(key)
            response.read.return_value = b'<link href="/static/style.css">'
            row, links = q.request(q.ADDRESSES[0], '/', ssl.create_default_context())
            self.assertTrue(row['tls_verified'])
            self.assertTrue(row['response_ok'])
            self.assertEqual(links, [('asset', '/static/style.css')])
            response.read.assert_called_once_with(q.BODY_LIMIT+1)
            client.request.assert_called_once_with('GET', '/', headers={'Host': q.HOST, 'Connection': 'close', 'Accept-Encoding': 'identity'})
            self.assertNotIn('secret', json.dumps(row))
            self.assertNotIn('body', row)

    def test_verification_failure_stops_family_without_bypass(self):
        with patch.object(q, 'request', return_value=({'tls_verified': False, 'error_type': 'SSLCertVerificationError'}, [])) as request:
            row = q.probe_family(q.ADDRESSES[0], None)
            request.assert_called_once_with(q.ADDRESSES[0], '/', None)
            self.assertFalse(row['page_asset_graph_accepted'])

    def test_discovery_is_bounded_and_acceptance_needs_css_and_png(self):
        def respond(address, path, context):
            depth = path.count('x')
            return ({'path': path, 'tls_verified': True, 'response_ok': True, 'content_type': 'text/html'}, [('page', '/'+('x'*(depth+1))+'.html')])
        with patch.object(q, 'request', side_effect=respond) as request:
            result = q.probe_family(q.ADDRESSES[0], None)
            self.assertLessEqual(request.call_count, 5)
            self.assertFalse(result['page_asset_graph_accepted'])
        def complete(address, path, context):
            kind = 'image/png' if path.endswith('.png') else 'text/css' if path.endswith('.css') else 'text/html'
            links = [('asset', '/static/a.css'), ('graph', '/host/cpu-day.png')]
            return ({'path': path, 'tls_verified': True, 'response_ok': True, 'content_type': kind, 'png_signature': kind == 'image/png'}, links)
        with patch.object(q, 'request', side_effect=complete) as request:
            result = q.probe_family(q.ADDRESSES[0], None)
            self.assertTrue(result['page_asset_graph_accepted'])
            self.assertFalse(result['graph_freshness_accepted'])
            self.assertEqual(request.call_count, 4)

    def test_redirect_is_recorded_without_following_and_oversize_fails(self):
        for status, size in [(301, 20), (200, q.BODY_LIMIT+1)]:
            with self.subTest(status=status), patch.object(q, 'LiteralHTTPS') as connection:
                client = connection.return_value
                client.sock.version.return_value = 'TLSv1.3'
                client.sock.getsockname.return_value = ('::1', 1)
                client.sock.getpeercert.side_effect = [b'cert', {}]
                response = client.getresponse.return_value
                response.status = status
                response.getheader.side_effect = lambda key: 'text/html' if key == 'Content-Type' else 'https://evil.invalid/private?secret'
                response.read.return_value = b'x'*size
                row, links = q.request(q.ADDRESSES[0], '/', ssl.create_default_context())
                self.assertFalse(row['response_ok'])
                self.assertEqual(links, [])
                self.assertEqual(client.request.call_count, 1)
                self.assertNotIn('secret', json.dumps(row))

    def bundle(self, mutate=None, extra=False):
        files = {'qualify_dashboard.py': (ROOT/'qualify_dashboard.py').read_bytes(),
                 'inspect_apache.py': (ROOT/'inspect_apache.py').read_bytes(),
                 'test_qualify_dashboard.py': (ROOT/'test_qualify_dashboard.py').read_bytes(),
                 'known_hosts': b'host key', 'ca.pem': Path('/etc/ssl/certs/ca-certificates.crt').read_bytes(),
                 'candidate.conf': b'ServerName '+q.HOST.encode()}
        now = int(time.time())
        spec = {'operation_id': 'svmf-apache-qualification-20261020-v1', 'prepared_epoch': now, 'expires_epoch': now+86400,
                'addresses': q.ADDRESSES, 'hostname': q.HOST, 'members': {n: q.sha(d) for n, d in files.items()}}
        if mutate:
            mutate(spec)
        files['spec.json'] = q.encoded(spec)
        if extra:
            files['extra'] = b'extra'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return buffer.getvalue(), files

    def test_archive_scope_hash_expiry_members_fail_before_contact(self):
        for mutate in [lambda s: s.update(hostname='evil.invalid'), lambda s: s.update(addresses=['127.0.0.1', '::1']),
                       lambda s: s.update(prepared_epoch=1, expires_epoch=86401), lambda s: s['members'].update({'ca.pem': 'wrong'})]:
            raw, _ = self.bundle(mutate)
            with self.assertRaises(ValueError):
                q.unpack(raw, q.sha(raw))
        raw, _ = self.bundle(extra=True)
        with self.assertRaises(ValueError):
            q.unpack(raw, q.sha(raw))
        raw, _ = self.bundle()
        with self.assertRaises(ValueError):
            q.unpack(raw, 'wrong')

    def test_execute_is_single_use_one_ssh_then_two_families_even_if_ssh_fails(self):
        raw, files = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'inspection.tar').write_bytes(raw)
            (directory/'known_hosts').write_bytes(files['known_hosts'])
            with patch.object(q.subprocess, 'run', side_effect=TimeoutError('sensitive')) as ssh, patch.object(q, 'probe_family', return_value={'accepted': False}) as probe:
                result = q.execute(directory, q.sha(raw))
                self.assertEqual(ssh.call_count, 1)
                self.assertEqual(probe.call_count, 2)
                self.assertFalse(result['configuration_mutation'])
                self.assertFalse(result['network_change_accepted'])
                self.assertNotIn('sensitive', json.dumps(result))
                with self.assertRaises(FileExistsError):
                    q.execute(directory, q.sha(raw))
                self.assertEqual(ssh.call_count, 1)
                self.assertEqual(probe.call_count, 2)

    def test_changed_known_hosts_fails_without_contact_or_receipt(self):
        raw, files = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'inspection.tar').write_bytes(raw)
            (directory/'known_hosts').write_bytes(b'changed')
            with patch.object(q.subprocess, 'run') as ssh:
                with self.assertRaises(ValueError):
                    q.execute(directory, q.sha(raw))
                ssh.assert_not_called()
                self.assertFalse((directory/'execution.json').exists())

    def test_remote_config_selection_omits_key_env_and_sensitive_conditions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root/'vhost.conf'
            config.write_text('ServerName '+q.HOST+'\nSSLCertificateKeyFile /private.key\nSetEnv PRIVATE secret\nRequire ip ::1\nRewriteCond %{HTTP:Authorization} secret\n')
            with patch.object(a, 'CONFIG_ROOT', root), patch.object(a.os, 'geteuid', return_value=0), patch.object(a.stat, 'S_ISREG', return_value=True):
                info = config.stat()
                stat_result = MagicMock(st_mode=info.st_mode, st_uid=0, st_size=info.st_size)
                with patch.object(a.Path, 'stat', return_value=stat_result):
                    result = a.read_config(config)
                exported = json.dumps(result)
                self.assertNotIn('private.key', exported)
                self.assertNotIn('SetEnv', exported)
                self.assertNotIn('secret', exported)
                self.assertIn('Require ip ::1', exported)
            with patch.object(a, 'CONFIG_ROOT', root/'different'):
                with self.assertRaises(ValueError):
                    a.read_config(config)

    def test_remote_identity_drift_runs_no_commands(self):
        with patch.object(a.os, 'geteuid', return_value=1000), patch.object(a, 'run') as command:
            with self.assertRaises(ValueError):
                a.collect()
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
