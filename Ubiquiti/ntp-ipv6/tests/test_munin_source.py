"""Offline GET-only, redaction, archive and single-use boundaries."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('munin_source',Path(__file__).resolve().parents[1]/'inspect-munin-source.py')
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)


class SourceTests(unittest.TestCase):
    def test_write_other_path_and_auth_are_rejected_before_connection(self):
        api=r.API()
        with patch.object(r.socket,'create_connection') as connect:
            for method,path in [('POST',r.CLIENT),('PUT',r.RESERVATIONS),('DELETE',r.CLIENT),('GET','/outside'),('GET',r.CLIENT)]:
                with self.assertRaises(ValueError):api.request(method,path)
            connect.assert_not_called()

    def test_extract_only_target_reservation_and_no_invented_proof(self):
        rows={'meta':{'rc':'ok'},'data':[{'mac':r.MAC,'use_fixedip':True,'fixed_ip':'10.1.3.83','secret':'NEVER_EXPORT'},
                                      {'mac':'00:00:00:00:00:01','secret':'OTHER_CLIENT'}]}
        result=r.reservation(rows)
        self.assertTrue(result['matches_observed_source'])
        self.assertNotIn('NEVER_EXPORT',json.dumps(result));self.assertNotIn('OTHER_CLIENT',json.dumps(result))
        rows['data'][0].pop('use_fixedip');self.assertFalse(r.reservation(rows)['matches_observed_source'])
        rows['data'].append(dict(rows['data'][0]))
        with self.assertRaisesRegex(ValueError,'ambiguous'):r.reservation(rows)

    def test_reservation_response_validation(self):
        for value in ({'data':[]},{'meta':{'rc':'ok'},'data':[]},
                      {'meta':{'rc':'ok'},'data':[{'mac':r.MAC,'use_fixedip':'true'}]},
                      {'meta':{'rc':'ok'},'data':[{'mac':r.MAC,'fixed_ip':'not-an-ip'}]}):
            with self.assertRaises(ValueError):r.reservation(value)

    def test_tls_dns_failure_prevents_credentials(self):
        with patch.object(r.socket,'getaddrinfo',return_value=[(0,0,0,0,('192.0.2.1',443))]),patch.object(r.subprocess,'run') as credential:
            with self.assertRaisesRegex(ValueError,'DNS drift'):r.API().authenticate()
            credential.assert_not_called()

    def test_collect_is_fixed_get_and_checks_mac(self):
        class Fake:
            def __init__(self):self.calls=[]
            def authenticate(self):pass
            def request(self,method,path):
                self.calls.append((method,path))
                if path==r.CLIENT:return {'macAddress':r.MAC}
                return {'meta':{'rc':'ok'},'data':[{'mac':r.MAC,'use_fixedip':True,'fixed_ip':'10.1.3.83'}]}
        api=Fake();result=r.collect(api)
        self.assertEqual(api.calls,[('GET',r.CLIENT),('GET',r.RESERVATIONS)])
        self.assertFalse(result['ipv6_persistence_accepted'])

    def test_seal_tamper_expiry_and_replay_never_contact(self):
        with tempfile.TemporaryDirectory() as root:
            d=Path(root)/'fixture';s=r.seal(d);r.prepare(d,s['sha256'])
            r.write(d/'execution.json',b'{}')
            with patch.object(r,'API') as api:
                with self.assertRaises(FileExistsError):r.execute(d,s['sha256'])
                api.assert_not_called()
            with patch.object(r.time,'time',return_value=s['expires_epoch']):
                with self.assertRaisesRegex(ValueError,'expired'):r.prepare(d,s['sha256'])
            (d/'review.md').write_text('tampered')
            with self.assertRaisesRegex(ValueError,'input drift'):r.prepare(d,s['sha256'])

    def test_conflict_paths_are_mode_scoped_and_get_only(self):
        with patch.object(r.socket,'create_connection') as connect:
            for mode,method,path in [('reservation','GET',r.CLIENTS),('conflicts','POST',r.CLIENTS),
                                     ('conflicts','GET','/outside')]:
                with self.assertRaises(ValueError):r.API(mode).request(method,path)
            connect.assert_not_called()

    def test_conflict_projection_omits_raw_clients_and_unrelated_addresses(self):
        rows=[{'mac':r.MAC,'ip':r.DESIRED4,'hostname':'SECRET'},
              {'mac':'00:11:22:33:44:55','ipv6_addresses':[r.DESIRED6],'secret':'SECRET'},
              {'ip':'192.0.2.99','ipv6_addresses':['2001:db8::1']}]
        result=r.address_evidence(rows,'fixture');text=json.dumps(result)
        self.assertNotIn('SECRET',text);self.assertNotIn('00:11:22:33:44:55',text)
        self.assertNotIn('192.0.2.99',text);self.assertNotIn('2001:db8::1',text)
        self.assertEqual(result['matches'],[{'address':r.DESIRED4,'owner':'master'},
                                             {'address':r.DESIRED6,'owner':'other_or_unknown'}])
        self.assertEqual(r.address_evidence([{'ip':r.DESIRED4}],'fixture')['ipv6_field_rows'],0)

    def test_conflict_collect_and_seal_do_not_invent_address_availability(self):
        class Fake:
            def __init__(self):self.calls=[]
            def authenticate(self):pass
            def request(self,method,path):
                self.calls.append((method,path))
                if path==r.CLIENT:return {'macAddress':r.MAC}
                row=({'ip_subnet':'10.1.0.0/22','ipv6_subnet':'fd36:5aa8:6971:1::/64','secret':'SECRET'}
                     if path==r.NETWORKS else {'mac':r.MAC,'ip':r.DESIRED4,'use_fixedip':True,'fixed_ip':r.DESIRED4})
                return {'meta':{'rc':'ok'},'data':[row]}
        api=Fake();result=r.collect(api,'conflicts')
        self.assertEqual(api.calls,[('GET',x) for x in (r.CLIENT,r.RESERVATIONS,r.CLIENTS,r.NETWORKS)])
        self.assertFalse(result['reported_conflict']);self.assertFalse(result['address_available_proven'])
        self.assertFalse(result['ipv6_visibility_complete']);self.assertNotIn('SECRET',json.dumps(result))
        with tempfile.TemporaryDirectory() as root:
            d=Path(root)/'conflicts';sealed=r.seal(d,'conflicts');self.assertEqual(r.prepare(d,sealed['sha256'])['mode'],'conflicts')


if __name__=='__main__':unittest.main()
