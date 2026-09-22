import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import health_watch as h
import reconcile_route as r
import freeze
import run_bundle


def sample(t, standby=True):
    checks = {}
    for key in ['cluster_dns4','cluster_dns6','cluster_https4','cluster_https6',
                'primary_dns4','primary_dns6','primary_https4','primary_https6',
                'standby_dns4','standby_dns6','standby_https4','standby_https6']:
        checks[key] = {'ok':standby or not key.startswith('standby')}
    for label in h.NODES:
        role = 'MASTER' if label == 'primary' else ('BACKUP' if standby else 'FAULT')
        checks[label] = {'node':{'boot':label+'-boot','hostname':h.NODES[label][3],
            'addresses':list(h.VIPS) if label=='primary' else [],'services':['active']*4,
            'transition':{'MESSAGE':'VRRP_Group(PIHOLE_DUALSTACK) Syncing instances to '+role+' state',
                          '__MONOTONIC_TIMESTAMP':'1' if standby or label == 'primary' else '2'}}}
    return {'start':t,'end':t+.1,'checks':checks}


class Health(unittest.TestCase):
    def series(self):
        return [sample(t,not 10<=t<=15) for t in range(0,86,5)]
    def test_transient_fault_recovers_with_stable_window(self):
        result = h.evaluate(self.series(),5)
        self.assertIsNone(result['fatal']);self.assertTrue(result['stable'])
    def test_persistent_node_failure_is_rejected(self):
        data=[sample(0)]+[sample(t,False) for t in range(5,76,5)]
        self.assertEqual(h.evaluate(data,5)['fatal'],'standby_recovery_deadline')
    def test_cluster_failure_latches_after_recovery(self):
        data=self.series();data[4]['checks']['cluster_dns6']['ok']=False
        self.assertEqual(h.evaluate(data,5)['fatal'],'cluster_dns6_failed')
    def test_sampling_gap_is_not_success(self):
        data=self.series();del data[6:8]
        self.assertEqual(h.evaluate(data,5)['fatal'],'sampling_gap')
    def test_boot_change_fails(self):
        data=self.series();data[-1]['checks']['standby']['node']['boot']='new'
        self.assertEqual(h.evaluate(data,5)['fatal'],'standby_identity_changed')
    def test_vip_movement_fails(self):
        data=self.series();data[5]['checks']['standby']['node']['addresses']=['10.1.0.55']
        self.assertEqual(h.evaluate(data,5)['fatal'],'standby_vip_ownership_changed')
    def test_node_ssh_gap_can_recover_within_budget(self):
        data=self.series();data[2]['checks']['standby']['node']=None
        self.assertIsNone(h.evaluate(data,5)['fatal'])
    def test_primary_ssh_gap_is_not_accepted(self):
        data=self.series();data[2]['checks']['primary']['node']=None
        self.assertEqual(h.evaluate(data,5)['fatal'],'primary_evidence_unavailable')
    def test_primary_transition_between_samples_fails(self):
        data=self.series();data[4]['checks']['primary']['node']['transition']['__MONOTONIC_TIMESTAMP']='changed'
        self.assertEqual(h.evaluate(data,5)['fatal'],'primary_ha_transition')
    def test_rollback_recovery_uses_original_boot_baseline(self):
        data=self.series();data[0]['checks']['standby']['node']=None
        result=h.evaluate(data,0,baseline=sample(-5))
        self.assertIsNone(result['fatal']);self.assertTrue(result['stable'])
    def test_stale_gate_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);h.atomic(root/'health-status.json',{'end':0,'healthy':True,'stable':True})
            with self.assertRaisesRegex(RuntimeError,'stale'):h.gate(root,'stable',timeout=1)
    def test_dns_requires_exact_answer(self):
        good=';; ->>HEADER<<- opcode: QUERY, status: NOERROR\nj2-svpi4mf.local.theama.co. 60 IN A 10.1.2.170\n'
        with patch.object(h,'command',return_value={'rc':0,'stdout':good}):self.assertTrue(h.dns('::1')['ok'])
        with patch.object(h,'command',return_value={'rc':0,'stdout':good.replace('10.1.2.170','10.1.2.171')}):self.assertFalse(h.dns('::1')['ok'])
    def test_https_requires_tls_verified_204(self):
        with patch.object(h,'command',return_value={'rc':0,'stdout':'204'}) as cmd:
            self.assertTrue(h.https('::1','fixture.local')['ok'])
            self.assertNotIn('-k',cmd.call_args.args[0])
        with patch.object(h,'command',return_value={'rc':0,'stdout':'200'}):self.assertFalse(h.https('::1','fixture.local')['ok'])


class Archive(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.base=self.root/'state';self.base.mkdir(mode=0o700)
        self.profile=self.root/'profile';self.profile.write_bytes(b'original');self.profile.chmod(0o600)
        self.helper=self.root/'helper';self.helper.write_bytes(b'old helper');self.helper.chmod(0o644)
        self.state={'status':'rolled_back','profile':{'path':str(self.profile),'data':base64.b64encode(b'original').decode(),'sha256':r.digest(b'original'),'mode':0o600}}
        self.contract={'profile_path':str(self.profile),'consumed_bundle':'a'*64,'state':{'status':'rolled_back'},'profile_sha256':r.digest(b'original'),'files':{str(self.helper):r.digest(b'old helper')}}
        self.write()
    def write(self):
        (self.base/'state.json').write_text(json.dumps(self.state));(self.base/'state.json').chmod(0o600)
        (self.base/'lock').touch(mode=0o600)
    def act(self):
        r.archive(self.contract,self.base,self.root/'archive',os.getuid(),self.root)
    def test_archive_preserves_exact_state_and_helpers(self):
        raw=(self.base/'state.json').read_bytes();self.act()
        dest=self.root/'archive'/('a'*64)
        self.assertEqual((dest/'state/state.json').read_bytes(),raw)
        self.assertEqual((dest/'helper').read_bytes(),b'old helper')
        self.assertFalse(self.base.exists());self.assertEqual(self.profile.read_bytes(),b'original')
    def test_modified_profile_stops_before_archive(self):
        self.profile.write_bytes(b'drift')
        with self.assertRaises(RuntimeError):self.act()
        self.assertTrue(self.base.exists());self.assertFalse((self.root/'archive').exists())
    def test_modified_helper_stops_before_archive(self):
        self.helper.write_bytes(b'drift')
        with self.assertRaises(RuntimeError):self.act()
        self.assertTrue(self.base.exists())
    def test_unexpected_residue_is_preserved(self):
        (self.base/'surprise').touch()
        with self.assertRaises(RuntimeError):self.act()
        self.assertTrue((self.base/'surprise').exists())
    def test_nonterminal_state_refused(self):
        self.state['status']='pending_acceptance';self.write()
        with self.assertRaises(RuntimeError):self.act()
    def test_archive_collision_preserves_state(self):
        (self.root/'archive'/('a'*64)).mkdir(parents=True);(self.root/'archive').chmod(0o700)
        with self.assertRaises(FileExistsError):self.act()
        self.assertTrue(self.base.exists())
    def test_symlink_refused(self):
        self.helper.unlink();self.helper.symlink_to(self.profile)
        with self.assertRaises(RuntimeError):self.act()
    def test_copy_failure_leaves_original_state(self):
        with patch.object(r.shutil,'copyfile',side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):self.act()
        self.assertTrue(self.base.exists())


class Bundle(unittest.TestCase):
    def test_retry_freezes_and_verifies_all_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'bundle';identity=freeze.freeze(out,'standby_route_retry')
            m=run_bundle.verify(out,identity)
            for name in ['scripts/health_watch.py','scripts/node_health.py','scripts/reconcile_route.py','retry-contract.json','ansible/route.yaml']:
                self.assertIn(name,m['files'])
            (out/'retry-contract.json').write_text('{}')
            with self.assertRaises(ValueError):run_bundle.verify(out,identity)

class EntryPoints(unittest.TestCase):
    def test_node_collector_uses_real_output_shapes(self):
        import node_health
        def read(args):
            if args[0]=='hostname':return 'j1-svpihole00\n'
            if args[0]=='ip':return '[{"addr_info":[{"local":"10.1.0.54"}]}]'
            if args[0]=='systemctl':return 'active\n'*4
            if args[0]=='journalctl':return '{"MESSAGE":"VRRP_Group(PIHOLE_DUALSTACK) Syncing instances to BACKUP state","__MONOTONIC_TIMESTAMP":"10"}\n'
            raise AssertionError(args)
        with patch.object(node_health,'read',side_effect=read):
            value=node_health.collect()
        self.assertEqual(h.role(value),'BACKUP')
        self.assertEqual(value['addresses'],['10.1.0.54'])
    def test_monitor_preserves_failure_history(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            def broken():raise RuntimeError('collector failed')
            monitor=h.Monitor(root,probe=broken);monitor.start();monitor.thread.join(timeout=2)
            result=json.loads((root/'health-status.json').read_text())
            self.assertEqual(result['fatal'],'RuntimeError')
    def test_cli_marker_and_health_gate_without_host_contact(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            h.atomic(root/'health-status.json',{'end':time.monotonic(),'healthy':True,'stable':False,'fatal':None})
            for mode in ['healthy','mark','applied','mark-recovery']:
                subprocess.run([sys.executable,str(h.ROOT/'health_watch.py'),td,mode],check=True,timeout=3)
            self.assertTrue((root/'apply-marker.json').is_file())
            self.assertTrue((root/'applied-marker.json').is_file())
            self.assertTrue((root/'recovery-marker.json').is_file())
