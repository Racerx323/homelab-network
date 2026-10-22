"""Dashboard diagnostic success, redaction, response bounds and replay guards."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
LOADER = importlib.util.spec_from_file_location('probe', ROOT/'probe_dashboard.py')
p = importlib.util.module_from_spec(LOADER); LOADER.loader.exec_module(p)


class ProbeTests(unittest.TestCase):
    def test_status_empty_and_oversized_bodies_are_distinct_without_exporting_content(self):
        spec = {'port': 80, 'path': '/munin/', 'host_header': 'munin.local.theama.co'}
        for status, body in [(403, b'private'), (200, b''), (200, b'x'*65537), (200, b'healthy')]:
            with self.subTest(status=status, size=len(body)), patch.object(p.http.client, 'HTTPConnection') as client:
                response = client.return_value.getresponse.return_value
                response.status = status; response.read.return_value = body; response.getheader.return_value = None
                result = p.probe(spec, '10.1.3.83')
                self.assertEqual(result['status'], status)
                self.assertEqual(result['body_empty'], not body)
                self.assertEqual(result['body_exceeds_gate_limit'], len(body) > 65536)
                self.assertEqual(result['deployment_http_gate_passes'], status == 200 and 0 < len(body) <= 65536)
                self.assertNotIn('body', result)
                response.read.assert_called_once_with(65537)
                client.return_value.request.assert_called_once_with('GET', '/munin/', headers={'Host': spec['host_header'], 'Connection': 'close'})
                client.return_value.close.assert_called_once()

    def test_location_removes_credentials_query_values_and_arbitrary_paths(self):
        result = p.location('https://user:password@example.invalid/private-token?secret=value#token')
        rendered = json.dumps(result)
        for secret in ['password', 'private-token', 'value', 'user:', '#token']: self.assertNotIn(secret, rendered)
        self.assertEqual(result['hostname'], 'example.invalid'); self.assertEqual(result['path'], 'other')
        self.assertTrue(result['query_present'])

    def test_transport_failure_is_bounded_and_redacted(self):
        with patch.object(p.http.client, 'HTTPConnection') as client:
            client.return_value.request.side_effect = OSError('sensitive details')
            result = p.probe({'port': 80, 'path': '/munin/', 'host_header': 'host'}, '10.1.3.83')
        self.assertEqual(result['error_type'], 'OSError'); self.assertNotIn('sensitive', json.dumps(result))
        client.return_value.close.assert_called_once()

    def archive(self, extra=False, expired=False):
        source = (ROOT/'probe_dashboard.py').read_bytes()
        spec = {'operation_id': 'svmf-dashboard-test', 'prepared_epoch': int(time.time())-(90000 if expired else 0),
                'expires_epoch': int(time.time())-(3600 if expired else -86400), 'source_sha256': p.sha(source),
                'addresses': ['10.1.3.83', 'fd36:5aa8:6971:1::1234'], 'port': 80, 'path': '/munin/',
                'host_header': 'munin.local.theama.co'}
        spec['expires_epoch'] = spec['prepared_epoch']+86400
        files = {'probe_dashboard.py': source, 'spec.json': p.encoded(spec)}
        if extra: files['unexpected'] = b'extra'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, raw in files.items():
                item = tarfile.TarInfo(name); item.size = len(raw); archive.addfile(item, io.BytesIO(raw))
        return buffer.getvalue(), files

    def test_digest_member_and_expiry_fail_before_contact(self):
        for extra, expired in [(True, False), (False, True)]:
            raw, _ = self.archive(extra, expired)
            with self.assertRaises(ValueError): p.unpack(raw, p.sha(raw))
        raw, _ = self.archive()
        with self.assertRaises(ValueError): p.unpack(raw, 'wrong')

    def test_execute_is_once_with_exactly_two_gets_and_no_replay(self):
        raw, _ = self.archive()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); (directory/'inspection.tar').write_bytes(raw)
            with patch.object(p, 'probe', return_value={'status': 403}) as probe:
                result = p.execute(directory, p.sha(raw))
                self.assertEqual(probe.call_count, 2); self.assertFalse(result['target_configuration_mutation'])
                with self.assertRaises(FileExistsError): p.execute(directory, p.sha(raw))
                self.assertEqual(probe.call_count, 2)


if __name__ == '__main__':
    unittest.main()
