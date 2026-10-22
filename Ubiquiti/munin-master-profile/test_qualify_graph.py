"""Offline targeted discovery, scope/integrity and single-use execution contracts."""
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
LOADER = importlib.util.spec_from_file_location('graph', ROOT/'qualify_graph.py')
g = importlib.util.module_from_spec(LOADER)
LOADER.loader.exec_module(g)


class GraphTests(unittest.TestCase):
    def test_descends_master_domain_and_retrieves_css_and_daily_graph(self):
        helper = MagicMock()
        def request(address, path, context):
            links = {g.SEED: [('page', '/other/index.html'), ('page', '/J1-SVMF/master/index.html')],
                     '/J1-SVMF/master/index.html': [('asset', '/static/style-new.css'), ('graph', '/J1-SVMF/master/cpu-day.png')]}.get(path, [])
            kind = 'image/png' if path.endswith('.png') else 'text/css' if path.endswith('.css') else 'text/html'
            return {'path': path, 'tls_verified': True, 'response_ok': True, 'content_type': kind, 'png_signature': kind == 'image/png'}, links
        helper.request.side_effect = request
        result = g.discover(helper, g.ADDRESSES[0], None)
        paths = [c.args[1] for c in helper.request.call_args_list]
        self.assertEqual(paths, [g.SEED, '/J1-SVMF/master/index.html', '/static/style-new.css', '/J1-SVMF/master/cpu-day.png'])
        self.assertTrue(result['accepted'])
        self.assertFalse(result['graph_freshness_accepted'])

    def test_four_page_bound_and_depth_first_children_before_siblings(self):
        helper = MagicMock()
        def request(address, path, context):
            links = [('page', '/J1-SVMF/child'+str(len(path))+'.html'), ('page', '/J1-SVMF/sibling.html')]
            return {'path': path, 'tls_verified': True, 'response_ok': True, 'content_type': 'text/html'}, links
        helper.request.side_effect = request
        result = g.discover(helper, g.ADDRESSES[0], None)
        self.assertLessEqual(helper.request.call_count, 4)
        self.assertFalse(result['accepted'])
        self.assertNotEqual(helper.request.call_args_list[2].args[1], '/J1-SVMF/sibling.html')

    def test_failed_tls_stops_without_retry_and_redirects_have_no_links(self):
        helper = MagicMock()
        helper.request.return_value = ({'tls_verified': False}, [])
        self.assertFalse(g.discover(helper, g.ADDRESSES[1], None)['accepted'])
        self.assertEqual(helper.request.call_count, 1)
        helper.reset_mock()
        helper.request.return_value = ({'tls_verified': True, 'status': 301, 'response_ok': False}, [])
        self.assertFalse(g.discover(helper, g.ADDRESSES[1], None)['accepted'])
        self.assertEqual(helper.request.call_count, 1)

    def test_graph_scope_rejects_other_domains_and_long_range_graphs(self):
        self.assertTrue(g.eligible('graph', '/munin-cgi/munin-cgi-graph/J1-SVMF/master/cpu-day.png'))
        self.assertFalse(g.eligible('graph', '/other/master/cpu-day.png'))
        self.assertFalse(g.eligible('graph', '/J1-SVMF/master/cpu-year.png'))
        self.assertFalse(g.eligible('page', '/other/index.html'))
        self.assertFalse(g.eligible('asset', '/other/style.css'))

    def bundle(self, mutate=None, extra=False):
        files = {n: (ROOT/n).read_bytes() for n in ('qualify_graph.py', 'qualify_dashboard.py', 'test_qualify_graph.py')}
        files.update({'ca.pem': Path('/etc/ssl/certs/ca-certificates.crt').read_bytes(), 'baseline.json': b'{}'})
        now = int(time.time())
        spec = {'operation_id': g.OPERATION, 'baseline_sha256': g.BASELINE, 'addresses': g.ADDRESSES,
                'seed': g.SEED, 'prepared_epoch': now, 'expires_epoch': now+86400,
                'members': {n: g.sha(d) for n, d in files.items()}}
        if mutate:
            mutate(spec)
        files['spec.json'] = g.encoded(spec)
        if extra:
            files['extra'] = b'extra'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return buffer.getvalue(), files

    def test_integrity_scope_and_expiry_rejected(self):
        for mutate in [lambda s: s.update(seed='/other/index.html'), lambda s: s.update(addresses=['127.0.0.1', '::1']),
                       lambda s: s.update(prepared_epoch=1, expires_epoch=86401), lambda s: s['members'].update({'ca.pem': 'wrong'})]:
            raw, _ = self.bundle(mutate)
            with self.assertRaises(ValueError):
                g.unpack(raw, g.sha(raw))
        raw, _ = self.bundle(extra=True)
        with self.assertRaises(ValueError):
            g.unpack(raw, g.sha(raw))
        raw, _ = self.bundle()
        with self.assertRaises(ValueError):
            g.unpack(raw, 'wrong')

    def test_execute_consumes_one_receipt_then_two_families_and_no_replay(self):
        raw, files = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, data in files.items():
                (directory/name).write_bytes(data)
            (directory/'inspection.tar').write_bytes(raw)
            with patch.object(g, '__file__', str(directory/'qualify_graph.py')), patch.object(g, 'ROOT', directory), patch.object(g, 'load_helper'), patch.object(g, 'discover', return_value={'accepted': False}) as discover:
                result = g.execute(directory, g.sha(raw))
                self.assertEqual(discover.call_count, 2)
                self.assertFalse(result['configuration_mutation'])
                with self.assertRaises(FileExistsError):
                    g.execute(directory, g.sha(raw))
                self.assertEqual(discover.call_count, 2)

    def test_changed_helper_rejected_before_import_or_contact(self):
        raw, files = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'inspection.tar').write_bytes(raw)
            (directory/'qualify_graph.py').write_bytes(files['qualify_graph.py'])
            (directory/'qualify_dashboard.py').write_bytes(b'changed')
            with patch.object(g, '__file__', str(directory/'qualify_graph.py')), patch.object(g, 'ROOT', directory), patch.object(g, 'load_helper') as load:
                with self.assertRaises(ValueError):
                    g.execute(directory, g.sha(raw))
                load.assert_not_called()
                self.assertFalse((directory/'execution.json').exists())


if __name__ == '__main__':
    unittest.main()
