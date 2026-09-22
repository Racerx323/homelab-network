import json
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import primary_route as r
import primary_health as h
import health_watch
from test_retry import sample
import proxy_route
import freeze
import run_bundle


def observation(t,phase='baseline',healthy=True):
    s=sample(t)
    for k in ('primary','standby'):
        n=s['checks'][k]['node'];n['ha_sha256']=h.HA_HASHES[k];n['profile_sha256']=h.STANDBY_PROFILE if k=='standby' else r.PROFILE_HASH;owner='standby' if phase in ('handoff','apply','settled') else 'primary'
        n['addresses']=list(health_watch.VIPS) if k==owner else []
        n['transition']['MESSAGE']='VRRP_Group(PIHOLE_DUALSTACK) Syncing instances to '+('MASTER' if k==owner else 'BACKUP')+' state'
        n['source']='fd36:5aa8:6971:1::'+('54' if k=='standby' else ('56' if phase=='baseline' else '53'))
        if k=='primary' and phase in ('handoff','apply','settled'):n['services']=['active','inactive','active','active']
    if not healthy:s['checks']['cluster_dns4']['ok']=False
    return s


class PrimaryHealth(unittest.TestCase):
    def test_handoff_with_short_probe_loss_can_settle(self):
        v=h.evaluate([observation(0),observation(5,'handoff',False),observation(10,'handoff')],[{'phase':'handoff','start':4}])
        self.assertIsNone(v['fatal']);self.assertTrue(v['healthy'])
    def test_cluster_loss_beyond_budget_fails(self):
        v=h.evaluate([observation(0)]+[observation(t,'handoff',False) for t in (5,10,15)],[{'phase':'handoff','start':4}])
        self.assertEqual(v['fatal'],'cluster_dns4_failed')
    def test_wrong_owner_does_not_pass_gate(self):
        v=h.evaluate([observation(0),observation(5)],[{'phase':'handoff','start':4}])
        self.assertFalse(v['healthy'])
    def test_stopped_primary_is_expected_during_route_phase(self):
        v=h.evaluate([observation(0)]+[observation(t,'settled') for t in range(5,76,5)],[{'phase':'settled','start':4}])
        self.assertIsNone(v['fatal']);self.assertTrue(v['stable'])
    def test_failed_failback_is_rejected(self):
        v=h.evaluate([observation(0)]+[observation(t,'settled') for t in range(5,76,5)],[{'phase':'failback','start':4}])
        self.assertIsNotNone(v['fatal'])
    def test_standby_source_drift_rejected(self):
        s=observation(5,'handoff');s['checks']['standby']['node']['source']='::bad'
        self.assertEqual(h.evaluate([observation(0),s],[{'phase':'handoff','start':4}])['fatal'],'standby_source_drift')
    def test_primary_source_checked_after_failback(self):
        data=[observation(0)]+[observation(t,'final') for t in range(5,76,5)]
        self.assertTrue(h.evaluate(data,[{'phase':'final','start':4}])['stable'])
        data[-1]['checks']['primary']['node']['source']='fd36:5aa8:6971:1::56'
        self.assertEqual(h.evaluate(data,[{'phase':'final','start':4}])['fatal'],'primary_source_mismatch')


class PrimaryRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.route_root=self.root/'route';self.route_root.mkdir()
        self.calls=[];self.transactions=[];self.service='active'
        self.state={'status':'prepared','boot':'boot','profile':{'sha256':r.PROFILE_HASH},'journal_cursor':'cursor'}
        r.save(self.root,self.state)
        self.patcher=patch.object(r.route,'BASE',self.route_root);self.patcher.start();self.addCleanup(self.patcher.stop)
    def call(self,a):
        self.calls.append(a)
        if a==['hostname','-s']:return 'j1-svpihole0'
        if a[0]=='cat':return 'boot'
        if a[:2]==['systemctl','stop']:self.service='inactive';return ''
        if a[:2]==['systemctl','start']:self.service='active';return ''
        if a[0]=='systemctl':return self.service
        raise AssertionError(a)
    def transaction(self,a):
        self.transactions.append(a)
        if a=='apply':(self.route_root/'state.json').write_text('{}')
    def act(self,a):
        r.dispatch(a,self.root,self.call,self.transaction,lambda _: {'sha256':r.PROFILE_HASH})
    def test_successful_phase_sequence(self):
        for a in ('handoff','apply','failback','accept'):self.act(a)
        self.assertEqual(json.loads((self.root/'state.json').read_text())['status'],'accepted')
        self.assertEqual(self.transactions,['apply','accept'])
        self.assertIn(['systemctl','stop',r.TIMER],self.calls)
    def test_failed_handoff_recovery_does_not_mutate_route(self):
        self.act('handoff');self.act('rollback')
        self.assertEqual(self.transactions,[]);self.assertEqual(self.service,'active')
    def test_controller_loss_before_apply_restores_service(self):
        self.act('handoff');self.act('expire')
        self.assertEqual(self.service,'active');self.assertEqual(self.transactions,[])
    def test_controller_loss_after_apply_restores_route_and_service(self):
        self.act('handoff');self.act('apply');self.act('expire')
        self.assertEqual(self.transactions,['apply','rollback']);self.assertEqual(self.service,'active')
    def test_rollback_error_still_restarts_keepalived(self):
        self.act('handoff');self.act('apply')
        def broken(a):raise RuntimeError('route failed')
        with self.assertRaises(RuntimeError):r.dispatch('rollback',self.root,self.call,broken)
        self.assertEqual(self.service,'active')
        self.assertEqual(json.loads((self.root/'state.json').read_text())['status'],'recovery_failed')
    def test_expiry_after_accept_does_not_undo_route(self):
        for a in ('handoff','apply','failback','accept'):self.act(a)
        self.act('expire');self.assertEqual(self.transactions,['apply','accept'])
    def test_apply_while_keepalived_active_is_rejected(self):
        self.state['status']='handoff';r.save(self.root,self.state)
        with self.assertRaises(RuntimeError):self.act('apply')
        self.assertEqual(self.transactions,[])
    def test_invalid_phase_never_stops_service(self):
        with self.assertRaises(RuntimeError):self.act('failback')
        self.assertNotIn(['systemctl','stop','keepalived'],self.calls)
    def test_shared_transaction_requires_explicit_primary_mode(self):
        with self.assertRaises(RuntimeError):proxy_route.transaction('apply',r.load_policy(),'pihole0',r.UUID,call=self.call)
    def test_primary_freeze_and_tamper_rejection(self):
        b=self.root/'bundle';identity=freeze.freeze(b,'primary_route');m=run_bundle.verify(b,identity)
        self.assertIn('scripts/primary_route.py',m['files']);self.assertIn('ansible/primary-route.yaml',m['files'])
        (b/'scripts/primary_route.py').write_text('changed')
        with self.assertRaises(ValueError):run_bundle.verify(b,identity)


class SharedPrimaryTransaction(unittest.TestCase):
    def test_apply_accept_with_restored_vips(self):
        from test_route_transaction import Model
        with tempfile.TemporaryDirectory() as td:
            m=Model(Path(td));owner=[False]
            def call(a):
                if a==['hostname','-s']:return 'j1-svpihole0'
                if 'GENERAL.CON-UUID' in a:return r.UUID
                if 'address' in a:
                    addresses=['fd36:5aa8:6971:1::53']+(list(health_watch.VIPS) if owner[0] else [])
                    return json.dumps([{'addr_info':[{'local':x} for x in addresses]}])
                out=m.call(a)
                return out.replace('fd36:5aa8:6971:1::54','fd36:5aa8:6971:1::53')
            def act(a):
                proxy_route.transaction(a,r.load_policy(),'pihole0',r.UUID,call=call,save=m.save,root=m.root,
                                        snapshot=m.snapshot,restore=m.restore,locate=lambda _: '/profile',primary=True)
            act('apply');self.assertTrue(m.installed)
            with self.assertRaisesRegex(RuntimeError,'address drift'):act('accept')
            owner[0]=True;act('accept')
            self.assertEqual(m.saved['status'],'accepted')
            self.assertFalse(m.stopped_timer)  # Outer primary state owns watchdog disarm.
