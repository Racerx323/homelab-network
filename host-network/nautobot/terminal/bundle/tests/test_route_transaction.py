#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import network_policy as p
import proxy_route as r

UUID = '3078e1cc-2e08-3745-b5e4-a60426628c39'


class Model:
    def __init__(self, root):
        self.root = root; self.routes = ''; self.installed = False
        self.saved = {}; self.commands = []; self.fail = None
        self.hash = 'before'; self.stopped_timer = False
    def save(self, value):
        self.saved = json.loads(json.dumps(value))
        (self.root / 'state.json').write_text(json.dumps(value))
    def snapshot(self, path):
        return {'path': path, 'sha256': self.hash, 'data': '', 'mode':384,'uid':0,'gid':0}
    def restore(self, snap, expected):
        if expected and self.hash != expected: raise RuntimeError('drift')
        self.hash = 'before'; self.routes = ''
    def call(self, a):
        self.commands.append(a)
        if self.fail and self.fail(a): raise RuntimeError('injected')
        if a == ['nmcli','--version']: return 'nmcli tool, version 1.42.4'
        if a == ['cat','/proc/sys/kernel/random/boot_id']:return 'boot-fixture'
        if a == ['hostname','-s']: return 'j1-svpihole00'
        if 'GENERAL.CON-UUID' in a: return UUID
        if a[:3] == ['nmcli','-g','ipv6.routes']: return self.routes
        if a[:4] == ['ip','-6','-j','route']:
            if 'get' in a: return json.dumps([{'prefsrc':'fd36:5aa8:6971:1::54'}])
            return json.dumps([{'dst':'fd36:5aa8:6971:1::170/128','dev':'eth0'}] if self.installed else [])
        if 'address' in a: return json.dumps([{'addr_info':[{'local':'fd36:5aa8:6971:1::54'}]}])
        if '+ipv6.routes' in a: self.routes='owned';self.hash='after'; return ''
        if '-ipv6.routes' in a: self.routes='';self.hash='before';return ''
        if a == ['nmcli','device','reapply','eth0']: self.installed=bool(self.routes);return ''
        if a[:3] == ['nmcli','connection','load']: return ''
        if a == ['id','-u','caddy']: return '994'
        if a == ['systemctl','stop','nautobot-proxy-route-retry-rollback.timer']:self.stopped_timer=True;return ''
        raise AssertionError(a)
    def act(self, action):
        r.transaction(action,p.load_policy(),'pihole00',UUID,call=self.call,save=self.save,
                      root=self.root,snapshot=self.snapshot,restore=self.restore,locate=lambda _: '/profile')


class Transaction(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.m=Model(Path(self.tmp.name))
    def test_apply_and_accept(self):
        self.m.act('apply'); self.assertTrue(self.m.installed)
        self.m.act('accept'); self.assertEqual(self.m.saved['status'],'accepted')
        self.m.act('expire'); self.assertTrue(self.m.installed)
        self.assertTrue(self.m.stopped_timer)
    def test_accepted_reapply_is_verified_noop(self):
        self.m.act('apply');self.m.act('accept')
        before=len([a for a in self.m.commands if '+ipv6.routes' in a])
        self.m.act('apply')
        self.assertEqual(before,len([a for a in self.m.commands if '+ipv6.routes' in a]))
    def test_controller_loss_rolls_back(self):
        self.m.act('apply'); self.m.act('expire')
        self.assertFalse(self.m.installed); self.assertEqual(self.m.hash,'before')
    def test_partial_reapply_failure_rolls_back(self):
        self.m.fail=lambda a:a==['nmcli','device','reapply','eth0']
        with self.assertRaises(RuntimeError):self.m.act('apply')
        self.m.fail=None; self.m.act('expire')
        self.assertEqual(self.m.hash,'before'); self.assertFalse(self.m.installed)
    def test_concurrent_drift_blocks_rollback(self):
        self.m.act('apply'); self.m.hash='someone-else'
        with self.assertRaises(RuntimeError):self.m.act('rollback')
        self.assertTrue(self.m.installed)
    def test_existing_route_rejected(self):
        self.m.installed=True
        with self.assertRaises(RuntimeError):self.m.act('apply')
        self.assertFalse(self.m.saved)
    def test_timeout_before_apply_is_noop(self):
        self.m.act('expire');self.assertFalse(self.m.saved)
    def test_rollback_failure_retained(self):
        self.m.act('apply');self.m.fail=lambda a:a[:3]==['nmcli','connection','load']
        with self.assertRaises(RuntimeError):self.m.act('expire')
        self.assertEqual(self.m.saved['status'],'pending_acceptance')
    def test_second_apply_requires_reconciliation(self):
        self.m.act('apply')
        with self.assertRaises(RuntimeError):self.m.act('apply')


if __name__ == '__main__':unittest.main(verbosity=2)
