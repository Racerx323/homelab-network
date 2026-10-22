"""Production wrapper contracts; no target contact or privileged commands."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
LOADER = importlib.util.spec_from_file_location('deployment', ROOT/'deploy.py')
d = importlib.util.module_from_spec(LOADER); LOADER.loader.exec_module(d)


def fixture():
    settings = json.loads((ROOT/'static-settings.json').read_bytes())['settings']
    spec = {'hostname': 'fixture', 'boot_id': 'boot', 'mac': 'mac', 'nm_version': 'version',
        'interface': 'eth0', 'uuid': 'uuid', 'profile': '/unused', 'settings': settings,
        'checkpoint_seconds': 300, 'addresses': ['10.1.3.83', 'fd36:5aa8:6971:1::83'],
        'original_sources': ['10.1.3.83', 'fd36:5aa8:6971:1::1234'],
        'dns': ['10.1.0.55', 'fd36:5aa8:6971:1::55'], 'search': 'local.theama.co',
        'resolver_name': 'ntp1.local.theama.co', 'ntp_addresses': ['10.1.0.51', 'fd36:5aa8:6971:1::51'],
        'gateway4': '10.1.0.1', 'manager': {'MainPID': '1'},
        'dashboard_paths': ['/', '/static/style-new.css', '/graph-day.png'], 'dashboard_leaf_sha256': 'leaf'}
    before = {'effective': {k: '' for k in settings} | {'connection.id': 'fixture', 'connection.timestamp': '1'},
        'services': {'NetworkManager.service': spec['manager']}, 'monotonic': time.monotonic(),
        'addresses': [{'local': spec['original_sources'][0], 'prefixlen': 22},
                      {'local': spec['original_sources'][1], 'prefixlen': 64},
                      {'local': '2001:db8::1', 'prefixlen': 64, 'scope': 'global'}],
        'routes': [{'dev': 'eth0', 'prefsrc': value} for value in spec['original_sources']],
        'defaults': [[{'gateway': '10.1.0.1'}], [{'gateway': 'fe80::1', 'protocol': 'ra'}]],
        'runtime': {'IP4.DNS[1]': spec['dns'][0], 'IP6.DNS[1]': spec['dns'][1], 'IP4.DOMAIN[1]': spec['search']},
        'resolver_config': {'nameserver': spec['dns'], 'search': [spec['search']]},
        'resolver4': ['10.1.0.51'], 'resolver6': ['fd36:5aa8:6971:1::51'], 'apprise': 200, 'smtp_banner': 'smtp'}
    candidate = copy.deepcopy(before)
    candidate['effective'].update(settings)
    candidate['effective']['connection.timestamp'] = '2'
    candidate['addresses'].append({'local': spec['addresses'][1], 'prefixlen': 64})
    candidate['routes'][1]['prefsrc'] = spec['addresses'][1]
    return spec, before, candidate


def dashboard(spec, family):
    return [{'address': spec['addresses'][0 if family == 4 else 1], 'path': path,
             'status': 200, 'tls_verified': True, 'response_ok': True, 'leaf_sha256': 'leaf',
             'content_type': 'image/png' if path.endswith('.png') else 'text/css' if path.endswith('.css') else 'text/html',
             'png_signature': path.endswith('.png')} for path in spec['dashboard_paths']]


class FakeGuard:
    def __init__(self, *args):
        self.phase = 'new'; self.path = None; self.device = '/device/1'; self.original = {}
        self.deadline = time.monotonic()+300; self.rolled_back = False
    def begin(self):
        self.path = '/checkpoint/1'; self.phase = 'guarded'
    def apply(self):
        self.phase = 'awaiting_confirmation'
    def commit(self, accept):
        if not all(accept().values()):
            raise ValueError('acceptance failed')
        self.phase = 'committed'
    def rollback(self):
        self.rolled_back = True; self.phase = 'rolled_back'


class DeploymentTests(unittest.TestCase):
    def test_reviewed_resolver_name_and_native_addresses(self):
        self.assertEqual(d.NTP_NAME, 'ntp1.local.theama.co')
        self.assertEqual(d.NTP_ADDRESSES, ['10.1.0.51', 'fd36:5aa8:6971:1::51'])
        self.assertEqual(d.resolver_addresses('10.1.0.51 STREAM ntp1.local.theama.co\n10.1.0.51 DGRAM\n', 4, d.NTP_ADDRESSES[0]), [d.NTP_ADDRESSES[0]])
        self.assertEqual(d.resolver_addresses('fd36:5aa8:6971:1::51 STREAM ntp1.local.theama.co\n', 6, d.NTP_ADDRESSES[1]), [d.NTP_ADDRESSES[1]])

    def test_mapped_wrong_empty_and_mixed_resolver_results_rejected(self):
        for raw in ('', '::ffff:10.1.0.51 STREAM ntp1.local.theama.co', '10.1.0.51 STREAM ntp1.local.theama.co',
                    'fd36:5aa8:6971:1::52 STREAM ntp1.local.theama.co',
                    'fd36:5aa8:6971:1::51 STREAM\n::ffff:10.1.0.51 DGRAM', 'not-an-address STREAM'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'resolver IPv6'):
                d.resolver_addresses(raw, 6, d.NTP_ADDRESSES[1])

    def test_lookup_failure_preserves_family_status_bounds_and_timeout(self):
        spec, _, _ = fixture()
        row = d.subprocess.CompletedProcess([], 2, b'', b'private error')
        with patch.object(d.subprocess, 'run', return_value=row), self.assertRaisesRegex(RuntimeError, 'getent IPv6 ntp1.*exit=2; stdout_bytes=0; stderr_bytes=13'):
            d.system_resolver(spec, 6)
        with patch.object(d.subprocess, 'run', side_effect=d.subprocess.TimeoutExpired('getent', 12)), self.assertRaisesRegex(RuntimeError, 'timed out: getent IPv4'):
            d.system_resolver(spec, 4)
        with patch.object(d.subprocess, 'run', return_value=d.subprocess.CompletedProcess([], 0, b'x'*262145, b'')), self.assertRaisesRegex(RuntimeError, 'getent IPv6.*exit=0; stdout_bytes=262145'):
            d.system_resolver(spec, 6)

    def test_same_mapped_baseline_and_observation_cannot_pass_dns_gate(self):
        spec, before, candidate = fixture()
        before['resolver6'] = candidate['resolver6'] = ['::ffff:10.1.0.51']
        self.assertFalse(d.checks(spec, before, candidate, True)['dns'])

    def test_all_gates_and_each_individual_regression(self):
        spec, before, candidate = fixture()
        self.assertTrue(all(d.checks(spec, before, candidate, True).values()))
        changes = [lambda x: x['addresses'].pop(),
            lambda x: x['addresses'][-1].update(tentative=True),
            lambda x: x['routes'][1].update(prefsrc=spec['original_sources'][1]),
            lambda x: x['defaults'][1].clear(),
            lambda x: x['runtime'].update({'IP6.DNS[2]': 'fd00::bad'}),
            lambda x: x['resolver_config'].update(search=['wrong']),
            lambda x: x['resolver4'].clear(),
            lambda x: x['services']['NetworkManager.service'].update(MainPID='2'),
            lambda x: x['effective'].update({'connection.id': 'foreign'}),
            lambda x: x['effective'].update({'ipv4.method': 'auto'}),
            lambda x: x.update(smtp_banner='changed')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                altered = copy.deepcopy(candidate); change(altered)
                self.assertFalse(all(d.checks(spec, before, altered, True).values()))

    def test_both_fresh_independent_observations_are_required(self):
        spec, before, candidate = fixture()
        state = {'bundle_sha256': 'digest', 'challenge': 'nonce', 'before': before}
        proof = {'bundle_sha256': 'digest', 'challenge': 'nonce', 'observations': [
            {'family': family, 'challenge': 'nonce', 'snapshot': candidate, 'dashboard': dashboard(spec, family)} for family in (4, 6)]}
        d.valid_observations(spec, state, proof)
        for key in ('challenge', 'bundle_sha256'):
            bad = copy.deepcopy(proof); bad[key] = 'wrong'
            with self.assertRaises(ValueError): d.valid_observations(spec, state, bad)
        bad = copy.deepcopy(proof); bad['observations'][1]['family'] = 4
        with self.assertRaises(ValueError): d.valid_observations(spec, state, bad)
        bad = copy.deepcopy(proof); bad['observations'][0]['snapshot']['monotonic'] -= 30
        with self.assertRaises(ValueError): d.valid_observations(spec, state, bad)
        bad = copy.deepcopy(proof); bad['observations'][0]['dashboard'][0]['status'] = 500
        with self.assertRaises(ValueError): d.valid_observations(spec, state, bad)

    def transaction(self, failure=None):
        spec, before, candidate = fixture()
        guard = FakeGuard()
        original_apply = guard.apply
        def apply():
            original_apply()
            if failure == 'after_write': raise RuntimeError('after actual write')
        guard.apply = apply
        if failure == 'rollback':
            guard.rollback = lambda: (_ for _ in ()).throw(ValueError('rollback failed'))
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); profile = directory/'profile'
            profile.write_bytes(b'original'); profile.chmod(0o600)
            spec.update(profile=str(profile), profile_sha256=d.sha(b'original'))
            d.write_new(directory/'spec.json', d.encoded(spec))
            d.save(directory/'state.json', {'phase': 'staged', 'bundle_sha256': 'digest', 'operation_id': 'test'})
            if failure == 'preflight': spec['profile_sha256'] = 'wrong'; d.save(directory/'spec.json', spec)
            def snapshot(_):
                if guard.phase in ('new', 'guarded', 'rolled_back'): return copy.deepcopy(before)
                return copy.deepcopy(candidate)
            def record(directory, state, phase, **fields):
                d.record_saved(directory, state, phase, **fields)
                if phase == 'awaiting_confirmation':
                    if failure in ('timeout', 'rollback', 'foreign', 'identity'):
                        guard.deadline = time.monotonic()+40
                    else:
                        proof = {'bundle_sha256': 'digest', 'challenge': state['challenge'], 'observations': [
                            {'family': f, 'challenge': state['challenge'], 'snapshot': candidate, 'dashboard': dashboard(spec, f)} for f in (4, 6)]}
                        d.write_new(directory/'confirmation.json', d.encoded(proof))
            effective = copy.deepcopy(before['effective'])
            if failure == 'foreign': effective['connection.id'] = 'foreign'
            services = copy.deepcopy(before['services'])
            if failure == 'identity': services['NetworkManager.service']['MainPID'] = '2'
            d.record_saved = d.record
            with patch.object(d, 'profile_record', return_value=(b'original', {'sha256': d.sha(b'original'), 'mode': 384, 'uid': 0, 'gid': 0})), \
                    patch.object(d, 'snapshot', side_effect=snapshot), patch.object(d, 'private'), \
                    patch.object(d, 'effective', return_value=effective), \
                    patch.object(d, 'identity', return_value=services), \
                    patch.object(d, 'record', side_effect=record), \
                    patch.object(d, 'guard_module') as module:
                module.return_value.Checkpoint.return_value = guard
                d.worker(directory)
            return json.loads((directory/'state.json').read_bytes()), guard, (directory/'original.nmconnection').exists()

    def test_commit_has_exact_durable_backup_and_complete_confirmation(self):
        state, guard, backup = self.transaction()
        self.assertEqual(state['phase'], 'committed'); self.assertTrue(backup)
        self.assertEqual(state['backup']['sha256'], d.sha(b'original'))
        self.assertFalse(guard.rolled_back)

    def test_preflight_failure_cannot_arm_or_write(self):
        state, guard, backup = self.transaction('preflight')
        self.assertEqual(state['phase'], 'preflight_failed'); self.assertIsNone(guard.path); self.assertFalse(backup)

    def test_timeout_and_interruption_after_write_restore_before_terminal_acceptance(self):
        for failure in ('timeout', 'after_write'):
            state, guard, backup = self.transaction(failure)
            self.assertEqual(state['phase'], 'rolled_back'); self.assertTrue(guard.rolled_back)
            self.assertIn('recovery', state); self.assertTrue(backup)

    def test_foreign_drift_and_unproven_rollback_hold(self):
        for failure in ('foreign', 'identity', 'rollback'):
            state, guard, backup = self.transaction(failure)
            self.assertEqual(state['phase'], 'recovery_held'); self.assertTrue(backup)
            if failure != 'rollback': self.assertFalse(guard.rolled_back)

    def test_confirmation_write_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'receipt'; d.write_new(path, b'first')
            with self.assertRaises(FileExistsError): d.write_new(path, b'second')
            self.assertEqual(path.read_bytes(), b'first')

    def test_profile_stability_ignores_atime_but_rejects_actual_file_change(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'profile'; path.write_bytes(b'original'); path.chmod(0o600)
            values = {name: getattr(path.stat(), name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            values.update(st_uid=0, st_gid=0)
            first = SimpleNamespace(**values, st_atime_ns=0)
            read = SimpleNamespace(**values, st_atime_ns=100)
            with patch.object(d, 'private'), patch.object(d.os, 'fstat', side_effect=[first, read]), \
                    patch.object(Path, 'lstat', return_value=read):
                raw, metadata = d.profile_record({'profile': str(path)})
            self.assertEqual(raw, b'original'); self.assertEqual(metadata['mode'], 0o600)
            changed = SimpleNamespace(**(values | {'st_mtime_ns': values['st_mtime_ns']+1}), st_atime_ns=100)
            with patch.object(d, 'private'), patch.object(d.os, 'fstat', side_effect=[first, changed]), \
                    patch.object(Path, 'lstat', return_value=changed), self.assertRaises(ValueError):
                d.profile_record({'profile': str(path)})

    def test_no_symlinks_public_files_or_special_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path = directory/'file'; path.write_bytes(b''); path.chmod(0o644)
            with self.assertRaises(ValueError): d.private(path)
            path.chmod(0o600); d.private(path)
            link = directory/'link'; link.symlink_to(path)
            with self.assertRaises(ValueError): d.private(link)
            fifo = directory/'fifo'; os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError): d.private(fifo)

    def archive(self, extra=None, expired=False, resolver_name='ntp1.local.theama.co'):
        files = {name: b'fixture' for name in d.MEMBERS-{'spec.json'}}
        spec = {'operation_id': 'svmf-network-test', 'prepared_epoch': int(time.time())-(90000 if expired else 0),
            'resolver_name': resolver_name, 'ntp_addresses': ['10.1.0.51', 'fd36:5aa8:6971:1::51'],
            'expires_epoch': int(time.time())+100, 'members': {name: d.sha(raw) for name, raw in files.items()}}
        files['spec.json'] = d.encoded(spec)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as stream:
            for name, raw in list(files.items())+([extra] if extra else []):
                entry = tarfile.TarInfo(name); entry.size = len(raw)
                stream.addfile(entry, io.BytesIO(raw))
        return archive.getvalue()

    def test_closed_bundle_integrity_expiry_and_read_only_expired_inspection(self):
        raw = self.archive(); d.unpack(raw, d.sha(raw))
        raw = self.archive(resolver_name='ntp2.local.theama.co')
        with self.assertRaisesRegex(ValueError, 'reviewed NTP resolver'):
            d.unpack(raw, d.sha(raw))
        with self.assertRaises(ValueError): d.unpack(raw, 'wrong')
        for extra in (('../escape', b'x'), ('spec.json', b'x')):
            raw = self.archive(extra)
            with self.assertRaises(ValueError): d.unpack(raw, d.sha(raw))
        raw = self.archive(expired=True)
        with self.assertRaises(ValueError): d.unpack(raw, d.sha(raw))
        d.unpack(raw, d.sha(raw), check_expiry=False)

    def test_controller_consumes_before_contact_and_refuses_replay(self):
        spec = {'addresses': ['10.1.3.83', 'fd00::83'], 'original_sources': ['10.1.3.83', 'fd00::1234'],
                'dashboard_host': 'fixture'}
        files = {'deploy.py': (ROOT/'deploy.py').read_bytes(), 'known_hosts': b'key', 'tls_probe.py': b'helper', 'ca.pem': b'ca'}
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); (directory/'deployment.tar').write_bytes(b'archive'); (directory/'known_hosts').write_bytes(b'key')
            (directory/'tls_probe.py').write_bytes(b'helper'); (directory/'ca.pem').write_bytes(b'ca')
            with patch.object(d, 'unpack', return_value=(spec, files)), patch.object(d, 'private'), \
                    patch.object(d, 'dashboard_https', side_effect=ValueError('preflight failed')), patch.object(d, 'transport') as transport:
                with self.assertRaises(ValueError): d.execute(directory, 'digest')
                self.assertTrue((directory/'execution.json').exists())
                with self.assertRaises(FileExistsError): d.execute(directory, 'digest')
                transport.assert_not_called()

    def test_https_proof_requires_all_assets_correct_family_trust_leaf_and_png(self):
        spec, _, _ = fixture()
        rows = dashboard(spec, 4)
        d.valid_dashboard(spec, spec['addresses'][0], rows)
        for change in [lambda r: r.pop(), lambda r: r[0].update(tls_verified=False),
                       lambda r: r[0].update(address=spec['addresses'][1]),
                       lambda r: r[0].update(leaf_sha256='wrong'),
                       lambda r: r[1].update(content_type='text/html'),
                       lambda r: r[2].update(png_signature=False),
                       lambda r: r[0].update(status=301)]:
            bad = copy.deepcopy(rows); change(bad)
            with self.assertRaises(ValueError): d.valid_dashboard(spec, spec['addresses'][0], bad)

    def test_changed_https_helper_or_trust_rejected_before_import_or_request(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'tls_probe.py').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                d.dashboard_https({'members': {'tls_probe.py': 'expected'}}, directory, '10.1.3.83')

    def test_inspection_reads_all_three_addresses_without_mutation_or_expiry_gate(self):
        spec = {'addresses': ['10.1.3.83', 'fd00::83'], 'original_sources': ['10.1.3.83', 'fd00::1234']}
        files = {'deploy.py': (ROOT/'deploy.py').read_bytes(), 'known_hosts': b'key', 'tls_probe.py': b'helper', 'ca.pem': b'ca'}
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'deployment.tar').write_bytes(b'archive'); (directory/'known_hosts').write_bytes(b'key')
            (directory/'tls_probe.py').write_bytes(b'helper'); (directory/'ca.pem').write_bytes(b'ca')
            d.write_new(directory/'execution.json', d.encoded({'sha256': 'digest'}))
            with patch.object(d, 'unpack', return_value=(spec, files)) as unpack, patch.object(d, 'private'), \
                    patch.object(d, 'remote', return_value={'fresh': True}) as remote, patch.object(d, 'transport') as transport:
                result = d.execute(directory, 'digest', inspect_only=True)
                self.assertEqual(len(result), 3)
                self.assertEqual(remote.call_count, 3)
                self.assertTrue(all(call.args[-1] == 'readback' for call in remote.call_args_list))
                self.assertFalse(unpack.call_args.kwargs['check_expiry'])
                self.assertEqual(len(list(directory.glob('inspection-*.json'))), 1)
                transport.assert_not_called()

    def test_install_has_supervised_worker_and_exclusive_stage(self):
        raw = self.archive()
        with tempfile.TemporaryDirectory() as temp, patch.object(d.os, 'geteuid', return_value=0), \
                patch.object(d, 'private'), patch.object(d, 'STATE', Path(temp)/'state'), patch.object(d, 'command') as command:
            result = d.install(raw, d.sha(raw))
            self.assertTrue(result['staged'])
            argv = command.call_args.args[0]
            for value in ('/usr/bin/systemd-run', '--property=Type=exec', '--property=Restart=no', '--property=RuntimeMaxSec=480'):
                self.assertIn(value, argv)
            directory = d.STATE/'svmf-network-test'
            self.assertEqual(json.loads((directory/'state.json').read_bytes())['phase'], 'staged')
            with self.assertRaises(FileExistsError): d.install(raw, d.sha(raw))
            self.assertEqual(command.call_count, 1)

    def test_started_worker_cannot_overwrite_or_replay_state(self):
        spec, before, candidate = fixture()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'spec.json').write_bytes(d.encoded(spec))
            original = d.encoded({'phase': 'write_intent', 'bundle_sha256': 'digest'})
            (directory/'state.json').write_bytes(original)
            with patch.object(d, 'guard_module') as module, self.assertRaises(ValueError):
                d.worker(directory)
            module.assert_not_called()
            self.assertEqual((directory/'state.json').read_bytes(), original)

    def test_ssh_uses_literals_pinned_keys_and_no_reused_connections(self):
        spec = {'user': 'pi', 'host_key_alias': 'svmf.local.theama.co'}
        argv = d.ssh(spec, Path('/private/known_hosts'), 6, 'fd36:5aa8:6971:1::83', 'safe')
        for option in ('-6', 'StrictHostKeyChecking=yes', 'ControlPath=none', 'ProxyCommand=none', 'GlobalKnownHostsFile=/dev/null'):
            self.assertIn(option, argv)
        with self.assertRaises(ValueError): d.ssh(spec, Path('/private/known_hosts'), 4, 'a hostname', 'safe')


if __name__ == '__main__':
    unittest.main()
