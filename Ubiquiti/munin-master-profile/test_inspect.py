"""Offline readiness collection, redaction and failure tests; no target contact."""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('readiness', Path(__file__).with_name('inspect.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Inspection(unittest.TestCase):
    def test_fields_are_closed_complete_and_unique(self):
        self.assertEqual(m.selected_fields('ipv4.method: auto\n', ['ipv4.method']), {'ipv4.method': 'auto'})
        for raw in ('', 'ipv4.method: auto\nipv4.method: manual', 'password: SECRET',
                    'ipv4.method: bad\x00value'):
            with self.subTest(raw=raw), self.assertRaises(ValueError) as error:
                m.selected_fields(raw, ['ipv4.method'])
            self.assertNotIn('SECRET', str(error.exception))

    def test_firewall_projection_drops_comments_commands_and_named_sets(self):
        raw = {'nftables': [{'rule': {'comment': 'SECRET', 'expr': [
            {'match': {'left': {'payload': {'protocol': 'ip6', 'field': 'saddr'}},
                       'op': '==', 'right': 'fd36:5aa8:6971:1::83'}},
            {'match': {'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}},
                       'op': '==', 'right': 4949}},
            {'match': {'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                       'op': 'in', 'right': '@SECRET'}},
            {'log': {'prefix': 'SECRET'}}, {'accept': None}]}}]}
        row = m.firewall_summary(json.dumps(raw)); text = json.dumps(row)
        self.assertNotIn('SECRET', text)
        self.assertIn('4949', text)
        self.assertEqual(row['unresolved_expressions'], 2)
        self.assertFalse(row['complete_policy_proof'])

    def run_capture(self, fail_optional=False, drift=False, root=0, fail_required=False, recovery=False):
        with tempfile.TemporaryDirectory() as directory:
            boot = Path(directory)/'boot'; boot.write_text('boot\n')
            def path(value):
                return boot if value == '/proc/sys/kernel/random/boot_id' else Path(value)
            calls = []; setting_calls = [0]
            def bounded(argv, **kwargs):
                calls.append(argv); out = ''; code = 0; stderr = 'SECRET'
                if argv[0].endswith('nmcli'):
                    if argv[-1] == '--active':
                        out = m.UUID+':eth0\n'
                    elif argv[-1] == m.UUID:
                        setting_calls[0] += 1
                        out = '\n'.join(key+': '+('changed' if drift and setting_calls[0] == 2 else 'auto')
                                        for key in m.FIELDS.split(','))
                    elif 'UUID,FILENAME' in argv:
                        out = m.UUID+':/etc/NetworkManager/system-connections/Wired connection 1.nmconnection\n'
                    elif '--version' in argv:
                        out = 'nmcli tool, version 1.42.4'
                    elif 'help' in argv:
                        out = '' if recovery else 'checkpoint\n'
                        if recovery:
                            stderr = 'Usage: device\ncheckpoint --timeout SECONDS\n'
                    else:
                        out = 'IP4.GATEWAY: 10.1.0.1\nIP6.GATEWAY: fe80::1\n'
                elif argv[0].endswith('/ip'):
                    out = '[]'
                    if fail_required:
                        out = 'SECRET'; code = 1
                elif argv[0].endswith('/nft'):
                    out = '{"nftables": []}' if not fail_optional else 'SECRET'
                    code = 0 if not fail_optional else 1
                elif argv[0].endswith('systemctl'):
                    out = 'MainPID=594\nNRestarts=0\nActiveState=active\n'
                return {'returncode': code, 'stdout': out, 'stderr': stderr}
            h = types.SimpleNamespace(bounded=bounded, sha=lambda data: 'hash',
                                      encoded=lambda value: json.dumps(value).encode())
            accepted = {'regular': True, 'uid': 0, 'gid': 0, 'mode': 0o600, 'size': 241, 'inode': 1}
            with patch.object(m, 'Path', side_effect=path), patch.object(m.os, 'geteuid', return_value=root), \
                    patch.object(m.socket, 'gethostname', return_value='J1-SVMF'), \
                    patch.object(m, 'metadata', side_effect=lambda p: {'missing': True} if str(p).startswith('/usr/share/man/') else accepted):
                collector = m.collect_recovery if recovery else m.collect
                result = collector({'operation_id': 'fixture', 'hostname': 'J1-SVMF', 'boot_id': 'boot'}, h)
            return result, calls

    def test_capture_is_read_only_and_does_not_claim_acceptance(self):
        result, calls = self.run_capture()
        self.assertTrue(result['capture_complete'], result)
        for key in ('target_mutation', 'static_configuration_accepted', 'recovery_qualified', 'address_available_proven'):
            self.assertFalse(result[key])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertTrue(all(argv[0] in ('/usr/bin/nmcli', '/usr/bin/systemctl', '/usr/sbin/ip',
                                       '/usr/bin/ss', '/usr/sbin/nft') for argv in calls))
        forbidden = {'modify', 'up', 'down', 'reapply', 'restart', 'reload', 'checkpoint', 'ping', 'exec'}
        self.assertFalse(any(forbidden.intersection(argv) for argv in calls))
        self.assertEqual([argv for argv in calls if 'help' in argv], [['/usr/bin/nmcli', 'device', 'help']])

    def test_optional_tool_failure_is_finding_without_raw_output(self):
        result, _ = self.run_capture(fail_optional=True)
        self.assertTrue(result['capture_complete'], result)
        self.assertNotIn('firewall', result)
        self.assertIn('firewall unavailable', ' '.join(result['findings']))
        self.assertNotIn('SECRET', json.dumps(result))

    def test_before_after_drift_and_wrong_root_fail_closed(self):
        result, _ = self.run_capture(drift=True)
        self.assertFalse(result['capture_complete'])
        result, calls = self.run_capture(root=1000)
        self.assertFalse(result['capture_complete']); self.assertEqual(calls, [])

    def test_required_command_failure_is_incomplete_and_redacted(self):
        result, _ = self.run_capture(fail_required=True)
        self.assertFalse(result['capture_complete'])
        self.assertIn('required command failed', result['error'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_profile_metadata_never_reads_contents_or_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'profile'; path.write_text('SECRET'); path.chmod(0o600)
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('content read')):
                row = m.metadata(path)
            self.assertNotIn('SECRET', json.dumps(row)); self.assertNotIn('sha256', row)
            link = Path(directory)/'link'; link.symlink_to(path)
            self.assertTrue(m.metadata(link)['indirect'])

    def test_recovery_reader_captures_help_stderr_without_checkpoint(self):
        result, calls = self.run_capture(recovery=True)
        self.assertTrue(result['capture_complete'], result)
        self.assertIn('checkpoint', result['device_help']['stderr'])
        self.assertEqual(result['device_help']['stdout'], '')
        self.assertTrue(result['checkpoint_documented'])
        self.assertFalse(result['timed_recovery_qualified'])
        self.assertFalse(result['independent_recovery_access_verified'])
        self.assertTrue(all(a[0] in ('/usr/bin/nmcli', '/usr/bin/systemctl') for a in calls))
        self.assertFalse(any('checkpoint' in a or 'modify' in a or 'up' in a for a in calls))
        self.assertNotIn('SECRET', json.dumps(result))
        result, calls = self.run_capture(recovery=True, root=1000)
        self.assertFalse(result['capture_complete']); self.assertEqual(calls, [])

    def test_checkpoint_excerpt_is_bounded(self):
        self.assertEqual(m.help_excerpt('unrelated help'), '')
        self.assertIn('checkpoint', m.help_excerpt('checkpoint\n--timeout\n'))
        with self.assertRaises(ValueError):
            m.help_excerpt('\n'.join('checkpoint' for _ in range(241)))


if __name__ == '__main__':
    unittest.main()
