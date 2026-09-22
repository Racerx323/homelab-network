#!/usr/bin/env python3
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import packet_probe as p
import packet_client as client
import packet_listener as listener
import packet_runner as runner
import packet_node as node
import freeze
import run_bundle


class Packet(unittest.TestCase):
    def test_nonce_peer_and_destination_all_required(self):
        v={'outcome':'response','source':'a','response':{'nonce':'n','peer':'a','local':'b'}}
        self.assertTrue(p.allowed(v,'n','a','b'))
        for key in ['nonce','peer','local']:
            wrong=json.loads(json.dumps(v));wrong['response'][key]='wrong'
            self.assertFalse(p.allowed(wrong,'n','a','b'))

    def test_denied_requires_timeout_source_and_matching_counter(self):
        v={'outcome':'timeout','source':'s'};before={'deny-v4':0,'deny-v6':0}
        self.assertTrue(p.denied(v,before,{'deny-v4':1,'deny-v6':0},4,'s'))
        for after in [before,{'deny-v4':0,'deny-v6':1},{'deny-v4':1,'deny-v6':1}]:
            self.assertFalse(p.denied(v,before,after,4,'s'))
        for outcome in ['error','response']:
            self.assertFalse(p.denied({'outcome':outcome,'source':'s'},before,{'deny-v4':1,'deny-v6':0},4,'s'))

    def test_closed_listener_is_error_not_denial(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
            v=client.probe('127.0.0.1',port)
        self.assertEqual(v['outcome'],'error')

    def test_partial_bind_failure_closes_earlier_socket(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
        with self.assertRaises(OSError):
            listener.serve('a'*32,['127.0.0.1','192.0.2.123'],port,lifetime=.01)
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('127.0.0.1',port))

    def test_listener_expiry_and_ipv6_only(self):
        with socket.socket(socket.AF_INET6) as reserved:
            reserved.bind(('::1',0));port=reserved.getsockname()[1]
        code="import sys;sys.path.insert(0,sys.argv[1]);from packet_listener import serve;serve('a'*32,['::1'],int(sys.argv[2]),lifetime=.3)"
        proc=subprocess.Popen([sys.executable,'-c',code,str(ROOT/'scripts'),str(port)],stdout=subprocess.PIPE,text=True)
        try:
            self.assertTrue(json.loads(proc.stdout.readline())['ready'])
            self.assertEqual(client.probe('::1',port)['response']['nonce'],'a'*32)
            self.assertEqual(client.probe('127.0.0.1',port)['outcome'],'error')
            proc.wait(timeout=3)
            self.assertEqual(client.probe('::1',port)['outcome'],'error')
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
            proc.stdout.close()

    def test_cleanup_failure_does_not_record_cleaned(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            (base/'state.json').write_text(json.dumps({'boot':boot,'status':'prepared'}))
            with patch.object(node,'BASE',base),patch.object(node.os,'geteuid',return_value=0), \
                 patch.object(node.guard,'trusted',side_effect=lambda p:p.read_text()), \
                 patch.object(node,'run',side_effect=['j2-svpi4mf','', 'LISTEN']):
                with self.assertRaisesRegex(RuntimeError,'listener remains'):
                    node.main('cleanup')
            self.assertEqual(json.loads((base/'state.json').read_text())['status'],'prepared')

    def test_incomplete_counter_set_rejected(self):
        with self.assertRaises(RuntimeError):node.counters({'nftables':[]})

    def test_failed_controller_never_claims_acceptance(self):
        with tempfile.TemporaryDirectory() as td,patch.object(runner,'check',return_value={'ssh':True}),patch.object(runner.subprocess,'run',side_effect=subprocess.TimeoutExpired('ansible',240)):
            self.assertEqual(runner.execute(Path(td),{},'a'*64),1)
            self.assertFalse(json.loads((Path(td)/'result.json').read_text())['accepted'])

    def test_freezer_binds_accepted_guard_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'bundle';sha=freeze.freeze(path,'packet_qualification');m=run_bundle.verify(path,sha)
            self.assertEqual(m['predecessor_archive']['commit'],'caf652f94716954c855c43a86fdac4c350595f1e')
            self.assertIn('rendered/guard-inputs.json',m['files'])

    def test_lifecycle_has_independent_timeout_and_always_cleanup(self):
        text=(ROOT/'ansible/packet.yaml').read_text()
        self.assertIn('RuntimeMaxSec=175',text);self.assertIn('TimeoutStopSec=5',text)
        self.assertIn('always:',text);self.assertIn('packet_node.py, cleanup',text)
        self.assertNotIn('backend_guard.py, remove',text)


if __name__=='__main__':unittest.main(verbosity=2)
