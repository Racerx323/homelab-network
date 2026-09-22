import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import proxy_route as r
import network_policy as p

class Settlement(unittest.TestCase):
    def check(self, failures=0, wrong=False, malformed=False):
        now=[0];calls=[0];samples=[]
        def call(a):
            if 'get' in a:
                calls[0]+=1
                if calls[0]<=failures:raise r.CommandFailure(a,2,'RTNETLINK answers: Network is unreachable')
                if malformed:return 'invalid'
                return json.dumps([{'prefsrc':'::1' if wrong else 'fd36:5aa8:6971:1::54'}])
            if 'address' in a:return json.dumps([{'addr_info':[{'local':'fd36:5aa8:6971:1::54'}]}])
            return json.dumps([{'dst':'fd36:5aa8:6971:1::170/128','dev':'eth0'}])
        def sleep(n):now[0]+=n
        fn=lambda:r.settle_route(p.load_policy(),'pihole00',['fd36:5aa8:6971:1::54'],call=call,clock=lambda:now[0],sleep=sleep,record=lambda x:samples.append(list(x)))
        return fn,now,samples
    def test_transient_failure_then_three_matches(self):
        fn,now,samples=self.check(failures=2);out=fn()
        self.assertEqual(len(out),5);self.assertEqual(out[-1]['consecutive_matches'],3)
        self.assertEqual(out[0]['command_failure']['returncode'],2)
        self.assertIn('Network is unreachable',out[0]['command_failure']['stderr'])
    def test_persistent_wrong_source_is_bounded(self):
        fn,now,samples=self.check(wrong=True)
        with self.assertRaises(RuntimeError):fn()
        self.assertLessEqual(now[0],20);self.assertEqual(len(samples[-1]),20)
    def test_malformed_evidence_fails_without_retry(self):
        fn,now,samples=self.check(malformed=True)
        with self.assertRaises(RuntimeError):fn()
        self.assertEqual(len(samples[-1]),1)
    def test_non_ip_diagnostics_do_not_leak_profile(self):
        e=r.CommandFailure(['nmcli','device','reapply','eth0'],1,'password=secret')
        self.assertNotIn('secret',str(e))
    def test_timeout_has_specific_command_and_status(self):
        with patch.object(r.subprocess,'run',side_effect=r.subprocess.TimeoutExpired(['ip'],1)):
            with self.assertRaises(r.CommandFailure) as got:r.run(['ip','-6','route'],timeout=1)
        self.assertTrue(got.exception.record['timed_out'])
        self.assertEqual(got.exception.record['argv'],['ip','-6','route'])

    def test_consumed_first_install_kind_blocked(self):
        import freeze
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, 'Consumed'):
                freeze.freeze(Path(td)/'bundle', 'standby_route')
            self.assertFalse((Path(td)/'bundle').exists())
