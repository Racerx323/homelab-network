#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import network_policy as p
import backend_guard as g
import proxy_route as r
import freeze as f
import run_bundle as runner


class Policy(unittest.TestCase):
    def test_fixed_sources_no_vip_and_non8080_untouched(self):
        rules = p.nft_rules(p.load_policy())
        self.assertNotIn('::56', rules)
        self.assertNotIn('ct state', rules)
        self.assertNotIn('flush', rules)
        self.assertEqual(rules.count('counter drop'), 2)
        self.assertIn('priority -110; policy accept', rules)

    def test_policy_rejects_broadened_sources(self):
        with tempfile.TemporaryDirectory() as td:
            value = p.load_policy()
            value['proxies']['pihole0']['ipv6'] = 'fd36:5aa8:6971:1::56'
            path = Path(td) / 'p.json'
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                p.load_policy(path)

    def test_route_scope_and_injection(self):
        cmds = p.route_commands(p.load_policy(), 'pihole00', '12345678-1234-1234-1234-123456789abc')
        self.assertEqual(cmds['apply'][-1], 'fd36:5aa8:6971:1::170/128 src=fd36:5aa8:6971:1::54')
        self.assertEqual(cmds['reapply'], ['nmcli', 'device', 'reapply', 'eth0'])
        with self.assertRaises(ValueError):
            p.route_commands(p.load_policy(), 'pihole00', 'bad; reboot')

    def test_semantic_comparison_retains_order_and_verdict(self):
        a = {'nftables': [{'metainfo': {'version': 'x'}}, {'rule': {'handle': 3, 'expr': [{'counter': {'packets': 1, 'bytes': 4}}, {'drop': None}]}}]}
        b = json.loads(json.dumps(a))
        b['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 90
        self.assertEqual(p.normalized_table(a), p.normalized_table(b))
        b['nftables'][1]['rule']['expr'][1] = {'accept': None}
        self.assertNotEqual(p.normalized_table(a), p.normalized_table(b))

    def test_guard_refuses_drift(self):
        with patch.object(g, 'table', return_value={'nftables': []}), patch.object(g, 'run') as run:
            with self.assertRaises(RuntimeError):
                g.apply('rules', 'wrong')
            run.assert_not_called()

    def test_guard_idempotent(self):
        value = {'nftables': []}
        with patch.object(g, 'table', return_value=value), patch.object(g, 'run') as run:
            g.apply('rules', p.digest(p.normalized_table(value)))
            run.assert_not_called()

    def test_guard_parser_failure_never_applies(self):
        with patch.object(g, 'table', return_value=None), patch.object(g, 'run', side_effect=RuntimeError('parser')) as run:
            with self.assertRaises(RuntimeError):
                g.apply('rules', 'digest')
            self.assertEqual(run.call_count, 1)
            self.assertIn('--check', run.call_args[0][0])

    def test_guard_retained_if_listener_present(self):
        with patch.object(g, 'run', return_value='LISTEN 8080') as run:
            with self.assertRaises(RuntimeError):
                g.remove('digest')
            self.assertEqual(run.call_count, 1)

    def test_absence_is_not_acceptance(self):
        self.assertFalse(p.acceptance({}))
        self.assertFalse(p.acceptance({'deny_v4': True, 'deny_v6': True}))

    def test_wrong_host_never_mutates(self):
        calls = []
        def fake(args):
            calls.append(args)
            return 'wrong-host'
        with self.assertRaises(RuntimeError):
            r.transaction('apply', p.load_policy(), 'pihole00', '12345678-1234-1234-1234-123456789abc', call=fake)
        self.assertEqual(calls, [])

    def test_review_bundle_is_not_executable(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'bundle'
            identity = f.freeze(out)
            manifest = json.loads((out / 'bundle.json').read_text())
            self.assertFalse(manifest['execution_ready'])
            self.assertEqual(len(identity), 64)
            for name, h in manifest['files'].items():
                self.assertEqual(f.hashlib.sha256((out / name).read_bytes()).hexdigest(), h)

    def test_runner_rejects_review_and_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'bundle'
            identity = f.freeze(out)
            with self.assertRaises(ValueError):
                runner.verify(out, identity)
            manifest = json.loads((out / 'bundle.json').read_text())
            manifest['kind'] = 'standby_route_retry'
            manifest['execution_ready'] = True
            raw = json.dumps(manifest).encode()
            (out / 'bundle.json').write_bytes(raw)
            identity = f.hashlib.sha256(raw).hexdigest()
            runner.verify(out, identity)
            (out / 'policy.json').write_text('{}')
            with self.assertRaises(ValueError):
                runner.verify(out, identity)



if __name__ == '__main__':
    unittest.main(verbosity=2)
