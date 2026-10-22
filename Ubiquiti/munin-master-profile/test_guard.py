"""Offline checkpoint ownership, confirmation and restoration contracts."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('guard', ROOT/'guard.py')
g = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(g)
UUID = '2cad90ef-210e-329a-bc55-9e23fa8160dd'


class Fake:
    def __init__(self):
        self.settings = {'ipv4.method': 'auto', 'ipv6.addresses': ''}
        self.pending = None; self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[0] == g.BUS:
            if argv[1] == 'get-property':
                return 'ao 1 "'+self.pending+'"' if self.pending else 'ao 0'
            method = argv[5]
            if method == 'GetDeviceByIpIface':
                return 'o "'+g.PATH+'/Devices/2"'
            if method == 'CheckpointCreate':
                self.before = dict(self.settings); self.pending = g.PATH+'/Checkpoint/1'
                return 'o "'+self.pending+'"'
            if method == 'CheckpointDestroy':
                if argv[-1] != self.pending:
                    raise ValueError('wrong checkpoint')
                self.pending = None; return ''
            if method == 'CheckpointRollback':
                self.settings = dict(self.before)
                return 'a{su} 1 "'+g.PATH+'/Devices/2" 0'
        if argv[-1] == '--active':
            return UUID+':eth0'
        if 'modify' in argv:
            self.settings.update(zip(argv[5::2], argv[6::2])); return ''
        if '-m' in argv:
            return '\n'.join(k+': '+(v or '--') for k, v in sorted(self.settings.items()))
        if 'up' in argv:
            return ''
        raise AssertionError(argv)


class GuardTests(unittest.TestCase):
    def make(self):
        backend = Fake()
        guard = g.Checkpoint('eth0', UUID,
            {'ipv4.method': 'manual', 'ipv6.addresses': 'fd36:5aa8:6971:1::83/64'}, command=backend)
        return guard, backend

    def test_guard_precedes_write_and_only_exact_complete_acceptance_commits(self):
        guard, backend = self.make()
        with patch.object(g.os, 'geteuid', return_value=0):
            guard.begin(); guard.apply()
        with self.assertRaises(ValueError):
            guard.commit(lambda: {'address4': True})
        self.assertIsNotNone(backend.pending)
        guard.commit(lambda: {key: True for key in g.LABELS})
        self.assertEqual(guard.phase, 'committed'); self.assertIsNone(backend.pending)
        with self.assertRaises(ValueError):
            guard.rollback()

    def test_explicit_and_timeout_rollback_restore_saved_settings(self):
        for timeout in (False, True):
            guard, backend = self.make()
            with patch.object(g.os, 'geteuid', return_value=0):
                guard.begin(); guard.apply()
            if timeout:
                backend.settings = dict(backend.before); backend.pending = None
                guard.confirm_timeout_rollback()
            else:
                guard.rollback()
            self.assertEqual(guard.phase, 'rolled_back'); self.assertEqual(backend.settings, backend.before)

    def test_existing_checkpoint_wrong_root_and_unguarded_write_reject(self):
        guard, backend = self.make()
        with self.assertRaises(ValueError):
            guard.apply()
        self.assertEqual(backend.calls, [])
        with patch.object(g.os, 'geteuid', return_value=1000), self.assertRaises(ValueError):
            guard.begin()
        self.assertEqual(backend.calls, [])
        backend.pending = g.PATH+'/Checkpoint/2'
        with patch.object(g.os, 'geteuid', return_value=0), self.assertRaises(ValueError):
            guard.begin()
        self.assertFalse(any('CheckpointDestroy' in a for a in backend.calls))

    def test_invalid_paths_and_expired_confirmation_do_not_destroy_guard(self):
        for raw in ('o ""', 'o "/"', 'o "'+g.PATH+'/Devices/2"'):
            with self.assertRaises(ValueError):
                g.object_path(raw, 'Checkpoint')
        guard, backend = self.make()
        with patch.object(g.os, 'geteuid', return_value=0):
            guard.begin(); guard.apply()
        with patch.object(g.time, 'monotonic', return_value=guard.deadline), self.assertRaises(ValueError):
            guard.commit(lambda: {key: True for key in g.LABELS})
        self.assertIsNotNone(backend.pending)

    def test_settings_preserve_ra_and_fixed_dns(self):
        recipe = json.loads((ROOT/'static-settings.json').read_text())
        settings = recipe['settings']
        self.assertEqual(settings['ipv4.method'], 'manual')
        self.assertEqual(settings['ipv4.addresses'], '10.1.3.83/22')
        self.assertEqual(settings['ipv6.method'], 'auto')
        self.assertEqual(settings['ipv6.addresses'], 'fd36:5aa8:6971:1::83/64')
        self.assertEqual(settings['ipv6.gateway'], '')
        self.assertEqual(settings['ipv6.ignore-auto-routes'], 'no')
        self.assertEqual(settings['ipv6.ignore-auto-dns'], 'yes')


if __name__ == '__main__':
    unittest.main()
