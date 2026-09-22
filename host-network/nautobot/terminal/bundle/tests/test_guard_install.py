#!/usr/bin/env python3
import hashlib
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import guard_checks as checks
import guard_runner as runner
import install_state as state
import rollback_install as rollback
import freeze
import run_bundle


class GuardInstall(unittest.TestCase):
    def test_privilege_drop_commands_do_not_inherit_controller_directory(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as td:
            try:
                os.chdir(td)
                self.assertEqual(checks.guard.run(['/bin/pwd']).strip(), '/')
            finally:
                os.chdir(previous)

    def test_unrelated_own_table_ignored_but_extra_rule_rejected(self):
        own = {'nftables': [{'table': {'family': 'inet', 'name': 'nautobot_backend'}},
                            {'chain': {'family': 'inet', 'table': 'nautobot_backend'}}]}
        with patch.object(checks.guard, 'run', side_effect=[json.dumps(own), '', '', '', '']):
            checks.unrelated()
        own['nftables'].append({'table': {'family': 'ip', 'name': 'unrelated'}})
        with patch.object(checks.guard, 'run', return_value=json.dumps(own)):
            with self.assertRaisesRegex(RuntimeError, 'unrelated'):
                checks.unrelated()

    def test_stopped_rejects_listener_active_unit_and_container(self):
        for answers in [['LISTEN'], ['', 'active\n' * 6], ['', 'inactive\n' * 6, '[{}]']]:
            with self.subTest(answers=answers), patch.object(checks.guard, 'run', side_effect=answers):
                with self.assertRaises(RuntimeError):
                    checks.stopped()

    def test_recovery_records_success_then_disarms(self):
        value = {'status': 'prepared', 'boot_id': 'boot'}
        with patch.object(checks, 'identity', return_value='boot'), patch.object(checks, 'unrelated'), \
             patch.object(checks, 'stopped'), patch.object(rollback, 'rollback') as undo, \
             patch.object(rollback, 'ALLOWED', set()), patch.object(rollback.guard, 'table', return_value=None), \
             patch.object(state, 'write') as write, patch.object(rollback.guard, 'run') as run:
            rollback.recover(value)
            undo.assert_called_once()
            self.assertEqual(value['status'], 'rolled_back')
            write.assert_called_once()
            self.assertEqual(run.call_args[0][0][-1], 'nautobot-backend-install-rollback.timer')

    def test_recovery_failure_records_manual_intervention_without_disarm(self):
        value = {'status': 'prepared', 'boot_id': 'boot'}
        with patch.object(checks, 'identity', return_value='boot'), patch.object(checks, 'unrelated'), \
             patch.object(rollback, 'rollback', side_effect=RuntimeError('listener present')), \
             patch.object(state, 'write') as write, patch.object(rollback.guard, 'run') as run:
            with self.assertRaises(RuntimeError):
                rollback.recover(value)
            self.assertEqual(value['status'], 'manual_intervention')
            write.assert_called_once()
            run.assert_not_called()

    def test_expired_watchdog_never_reverts_accepted(self):
        with patch.object(rollback, 'rollback') as undo:
            rollback.recover({'status': 'accepted'})
            undo.assert_not_called()

    def test_controller_baseline_failure_never_starts_ansible(self):
        with tempfile.TemporaryDirectory() as td, patch.object(runner, 'check', return_value={'ssh': False}), \
             patch.object(runner.subprocess, 'run') as run:
            self.assertEqual(runner.execute(Path(td), {}, 'a' * 64), 1)
            run.assert_not_called()

    def test_timeout_does_not_disarm_or_rerun(self):
        with tempfile.TemporaryDirectory() as td, patch.object(runner, 'check', return_value={'ssh': True}), \
             patch.object(runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ansible', 240)) as run:
            self.assertEqual(runner.execute(Path(td), {}, 'a' * 64), 1)
            self.assertEqual(run.call_count, 1)
            self.assertIn('300-second', json.loads((Path(td) / 'result.json').read_text())['recovery_note'])

    def test_nonzero_playbook_never_accepted_from_node_label(self):
        with tempfile.TemporaryDirectory() as td, patch.object(runner, 'check', return_value={'ssh': True}), \
             patch.object(runner.subprocess, 'run', side_effect=[
                 subprocess.CompletedProcess([], 1),
                 subprocess.CompletedProcess([], 0, '{"status":"accepted","boot_matches":true}', '')]):
            self.assertEqual(runner.execute(Path(td), {}, 'a' * 64), 1)

    def test_freeze_includes_exact_rendered_inputs_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as td, patch.object(freeze.subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 0, 'a' * 64 + '\n', '')):
            p = Path(td) / 'bundle'
            sha = freeze.freeze(p, 'guard_install')
            run_bundle.verify(p, sha)
            inputs = json.loads((p / 'rendered/installation.json').read_text())
            self.assertEqual(set(inputs['files']), rollback.ALLOWED)
            (p / 'rendered/rules.nft').write_text('tampered')
            with self.assertRaises(ValueError):
                run_bundle.verify(p, sha)

    def test_no_qualification_booleans_replace_real_baseline(self):
        text = (ROOT / 'ansible/guard.yaml').read_text()
        self.assertNotIn('guard_baseline_absent_verified', text)
        self.assertIn('install_state.py, prepare', text)
        self.assertLess(text.index('Verify watchdog armed'), text.index('Stage guard inputs'))
        self.assertLess(text.index('Verify management and monitoring'), text.index('Accept guard installation'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
