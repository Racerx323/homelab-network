"""Offline failure projection, scope, integrity and no-replay contracts."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
LOADER = importlib.util.spec_from_file_location('diagnostic', ROOT/'diagnose_preflight.py')
d = importlib.util.module_from_spec(LOADER)
LOADER.loader.exec_module(d)


class DiagnosticTests(unittest.TestCase):
    def bundle(self, mutate=None, extra=False):
        files = {n: (ROOT/n).read_bytes() for n in ('diagnose_preflight.py', 'test_diagnose_preflight.py')}
        files.update({'known_hosts': b'fixture', 'baseline.json': b'{}'})
        now = int(time.time())
        spec = {'operation_id': d.OPERATION, 'baseline_sha256': d.BASELINE, 'prepared_epoch': now,
                'expires_epoch': now+86400, 'members': {n: d.sha(v) for n, v in files.items()}}
        if mutate:
            mutate(spec)
        files['spec.json'] = d.encoded(spec)
        if extra:
            files['extra'] = b'extra'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, raw in files.items():
                entry = tarfile.TarInfo(name); entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        return buffer.getvalue(), files

    def test_scope_integrity_expiry_and_closed_members(self):
        for mutate in (lambda s: s.update(operation_id='foreign'),
                       lambda s: s.update(baseline_sha256='foreign'),
                       lambda s: s.update(prepared_epoch=1, expires_epoch=86401),
                       lambda s: s['members'].update({'known_hosts': 'wrong'})):
            raw, _ = self.bundle(mutate)
            with self.assertRaises(ValueError):
                d.unpack(raw, d.sha(raw))
        raw, _ = self.bundle(extra=True)
        with self.assertRaises(ValueError):
            d.unpack(raw, d.sha(raw))
        raw, _ = self.bundle()
        with self.assertRaises(ValueError):
            d.unpack(raw, 'wrong')

    def fixture(self):
        state = {'operation_id': d.FAILED_OPERATION, 'bundle_sha256': d.BASELINE,
                 'phase': 'preflight_failed', 'phase_before_failure': 'preflight',
                 'error': 'ValueError: exact original profile baseline drift', 'secret_extra': 'OMIT'}
        spec = {'operation_id': d.FAILED_OPERATION, 'profile': str(d.PROFILE),
                'profile_sha256': 'original', 'profile_metadata': {'inode': 1}}
        pinned = patch.object(d, 'BASELINE_SPEC_SHA', d.sha(d.encoded(spec)))
        pinned.start(); self.addCleanup(pinned.stop)
        def read(path):
            if path == d.STAGE/'state.json':
                return d.encoded(state), {}
            if path == d.STAGE/'spec.json':
                return d.encoded(spec), {}
            self.assertEqual(path, d.PROFILE)
            return b'PRIVATE PROFILE CONTENT', {'sha256': 'original', 'inode': 2}
        return state, read

    def test_failure_projection_reports_metadata_drift_without_exporting_profile(self):
        _, read = self.fixture()
        with patch.object(d, 'protected_read', side_effect=read), patch.object(d, 'identity', return_value='same'), patch.object(d, 'command', return_value='unit') as command:
            result = d.collect()
        self.assertTrue(result['capture_complete'])
        self.assertTrue(result['profile_content_matches_baseline'])
        self.assertFalse(result['profile_metadata_matches_baseline'])
        self.assertEqual(result['state']['error'], 'ValueError: exact original profile baseline drift')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('secret_extra', result['state'])
        self.assertEqual(command.call_args.args[0][1], 'show')

    def test_foreign_retained_operation_rejected_before_profile_read(self):
        state, read = self.fixture(); state['bundle_sha256'] = 'foreign'
        with patch.object(d, 'protected_read', side_effect=read) as reader, patch.object(d, 'identity', return_value='same'):
            with self.assertRaises(ValueError):
                d.collect()
        self.assertEqual(reader.call_count, 1)

    def test_manager_drift_rejects_capture(self):
        _, read = self.fixture()
        with patch.object(d, 'protected_read', side_effect=read), patch.object(d, 'identity', side_effect=['before', 'after']), patch.object(d, 'command', return_value='unit'):
            with self.assertRaises(ValueError):
                d.collect()

    def test_one_pinned_ipv4_session_and_receipt_prevents_replay(self):
        raw, files = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in files.items():
                d.write(directory/name, value)
            d.write(directory/'inspection.tar', raw)
            row = subprocess.CompletedProcess([], 0, d.encoded({'capture_complete': True}), b'')
            with patch.object(d.subprocess, 'run', return_value=row) as run:
                self.assertTrue(d.execute(directory, d.sha(raw))['capture_complete'])
                with self.assertRaises(FileExistsError):
                    d.execute(directory, d.sha(raw))
            self.assertEqual(run.call_count, 1)
            argv = run.call_args.args[0]
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('-4', argv)
            self.assertIn('pi@10.1.3.83', argv)
            self.assertEqual(argv[-1], 'cd / && /usr/bin/sudo -n /usr/bin/python3 -I -B - collect')

    def test_timeout_consumes_receipt(self):
        raw, files = self.bundle()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in files.items():
                d.write(directory/name, value)
            d.write(directory/'inspection.tar', raw)
            with patch.object(d.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 55)) as run:
                with self.assertRaises(ValueError):
                    d.execute(directory, d.sha(raw))
                with self.assertRaises(FileExistsError):
                    d.execute(directory, d.sha(raw))
            self.assertEqual(run.call_count, 1)

    def test_resolver_captures_both_named_families_after_negative_result(self):
        def probe(argv, timeout=5):
            if 'ahostsv4' in argv:
                return {'returncode': 2, 'stdout': ''}
            if 'ahostsv6' in argv:
                return {'returncode': 0, 'stdout': 'fd36:5aa8:6971:1::51 STREAM ntp1.local.theama.co\n'}
            return {'returncode': 0, 'stdout': ''}
        with patch.object(d, 'identity', return_value='same'), patch.object(d, 'resolver_file', return_value={'sha256': 'same'}), patch.object(d, 'resolver_command', side_effect=probe) as command, patch.object(Path, 'is_file', return_value=False):
            result = d.collect_resolver()
        self.assertTrue(result['capture_complete'])
        self.assertFalse(result['lookups']['ahostsv4']['expected_address_present'])
        self.assertTrue(result['lookups']['ahostsv6']['expected_address_present'])
        lookups = [c.args[0] for c in command.call_args_list if c.args[0][0] == '/usr/bin/getent']
        self.assertEqual(lookups, [['/usr/bin/getent', family, 'ntp1.local.theama.co'] for family in ('ahostsv4', 'ahostsv6')])

    def test_probe_preserves_nonzero_timeout_and_output_bound_separately(self):
        argv = ['/usr/bin/getent', 'ahostsv6', d.RESOLVER_NAME]
        with patch.object(d.subprocess, 'run', return_value=subprocess.CompletedProcess(argv, 2, b'', b'failure')):
            row = d.resolver_command(argv)
        self.assertEqual(row['returncode'], 2)
        self.assertNotIn('stderr', row)
        with patch.object(d.subprocess, 'run', side_effect=subprocess.TimeoutExpired(argv, 5)):
            self.assertEqual(d.resolver_command(argv)['error'], 'timeout')
        with patch.object(d.subprocess, 'run', return_value=subprocess.CompletedProcess(argv, 0, b'x'*65537, b'')):
            self.assertEqual(d.resolver_command(argv)['error'], 'output_bound')

    def test_resolver_bundle_lookup_scope_and_remote_dispatch(self):
        def resolver(spec):
            spec.update(operation_id=d.RESOLVER_OPERATION, kind='resolver', lookup_name=d.RESOLVER_NAME)
        raw, files = self.bundle(resolver)
        d.unpack(raw, d.sha(raw))
        wrong, _ = self.bundle(lambda s: (resolver(s), s.update(lookup_name='ntp2.local.theama.co')))
        with self.assertRaises(ValueError):
            d.unpack(wrong, d.sha(wrong))
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name, value in files.items():
                d.write(directory/name, value)
            d.write(directory/'inspection.tar', raw)
            row = subprocess.CompletedProcess([], 0, d.encoded({'capture_complete': True}), b'')
            with patch.object(d.subprocess, 'run', return_value=row) as run:
                d.execute(directory, d.sha(raw))
            self.assertTrue(run.call_args.args[0][-1].endswith(' collect-resolver'))
            self.assertEqual(run.call_args.kwargs['timeout'], 90)

    def test_resolver_file_rejects_unapproved_symlink_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'resolv.conf'
            private = Path(temp)/'private'
            private.write_text('must not read')
            path.symlink_to(private)
            with self.assertRaises(ValueError):
                d.resolver_file(path)


if __name__ == '__main__':
    unittest.main()
