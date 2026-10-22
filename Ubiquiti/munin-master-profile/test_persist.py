"""Offline profile parser, no-contact root guard and bounded review checks."""
import importlib.util
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('persist',Path(__file__).with_name('persist.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class ProfileTests(unittest.TestCase):
    def transaction(self,drift=False,override=False):
        """Exercise the real transaction with a fake NM backend and private files."""
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);runtime=root/'runtime.nmconnection';persistent=root/'etc/profile.nmconnection'
            persistent.parent.mkdir(mode=0o700)
            raw=('[connection]\nuuid='+m.UUID+'\nid='+m.NAME+'\ntype=ethernet\ninterface-name=eth0\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\naddr-gen-mode=3\n').encode()
            runtime.write_bytes(raw);runtime.chmod(0o600)
            boot=root/'boot';boot.write_text('boot\n')
            identities={name:root/Path(name).name for name in ('/var/lib/NetworkManager/secret_key','/etc/machine-id')}
            for path in identities.values():path.write_text('fixture identity');path.chmod(0o600)
            path_class=Path;stat_method=Path.stat;calls=[];written=False
            def path(value):
                if str(value)=='/proc/sys/kernel/random/boot_id':return boot
                if str(value)=='/var/lib/munin-master-profile':return root/'operations'
                return identities.get(str(value),path_class(value))
            def root_stat(p,**kwargs):
                info=stat_method(p,**kwargs)
                return types.SimpleNamespace(st_mode=info.st_mode&~0o022,st_uid=0,st_gid=0,
                    st_ino=info.st_ino,st_size=info.st_size,st_mtime_ns=info.st_mtime_ns)
            def record(p,**kwargs):
                data=path_class(p).read_bytes()
                return {'uid':0,'mode':0o600,'base64':base64.b64encode(data).decode(),
                        'sha256':hashlib.sha256(data).hexdigest()}
            def command(argv,**kwargs):
                nonlocal written
                calls.append(argv)
                if argv[1:3]==['connection','modify']:
                    persistent.write_bytes(raw);persistent.chmod(0o600);written=True;output=''
                elif '--version' in argv:output='nmcli tool, version 1.42.4\n'
                elif '-g' in argv:output=m.NAME+'\ndefault\n'
                elif '-m' in argv:output='settings changed' if written and drift else 'same effective settings'
                elif '--print-config' in argv:output='[connection]\nipv6.addr-gen-mode=eui64\n' if override else '[main]\nplugins=keyfile\n'
                elif 'UUID,DEVICE' in argv:output=m.UUID+':eth0\n'
                elif 'UUID,FILENAME' in argv:output=m.UUID+':'+str(persistent if written else runtime)+'\n'
                elif argv[0].endswith('systemctl'):output='MainPID=100\nInvocationID=fixture\nNRestarts=0\nActiveState=active\nSubState=running\n'
                elif argv[0].endswith('/ip'):output=json.dumps([{'dev':'eth0','prefsrc':m.ULA if '-6' in argv else m.IPV4}])
                else:raise AssertionError('unexpected command '+repr(argv))
                return {'returncode':0,'stdout':output,'stderr':''}
            h=types.SimpleNamespace(sha=lambda raw:hashlib.sha256(raw).hexdigest(),
                 encoded=lambda obj:json.dumps(obj,sort_keys=True).encode(),file_record=record,bounded=command)
            previous=os.umask(0o077)
            try:
                with patch.object(m,'RUNTIME',runtime),patch.object(m,'PERSISTENT',persistent), \
                     patch.object(m,'Path',side_effect=path),patch.object(path_class,'stat',root_stat), \
                     patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value='master'):
                    result=m.apply({'operation_id':'fixture','hostname':'master','boot_id':'boot'},h)
                files={'backup':(root/'operations/fixture/original-runtime-profile').exists(),
                       'runtime':runtime.exists(),'persistent':persistent.exists()}
            finally:os.umask(previous)
            return result,calls,files

    def test_success_saves_once_without_reactivation(self):
        result,calls,files=self.transaction()
        self.assertTrue(result['capture_complete'],result);self.assertTrue(result['running_network_unchanged'])
        self.assertEqual(sum(argv[1:3]==['connection','modify'] for argv in calls),1)
        self.assertFalse(any(word in argv for argv in calls for word in ('up','down','reload','reapply','restart')))
        self.assertTrue(all(files.values()))

    def test_global_policy_drift_submits_no_write(self):
        result,calls,files=self.transaction(override=True)
        self.assertFalse(result['write_intent']);self.assertFalse(files['persistent'])
        self.assertFalse(files['backup']);self.assertFalse(any(argv[1:3]==['connection','modify'] for argv in calls))

    def test_postwrite_drift_holds_without_delete_or_extra_mutation(self):
        result,calls,files=self.transaction(drift=True)
        self.assertFalse(result['capture_complete']);self.assertTrue(result['write_intent'])
        self.assertIn('held',result['recovery']);self.assertTrue(all(files.values()))
        self.assertEqual(sum(argv[1:3]==['connection','modify'] for argv in calls),1)

    def test_only_observed_profile_is_eligible(self):
        raw=('[connection]\nuuid='+m.UUID+'\nid='+m.NAME+'\ntype=ethernet\ninterface-name=eth0\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\naddr-gen-mode=3\n').encode()
        self.assertEqual(m.profile(raw).get('ipv6','addr-gen-mode'),'3')
        for bad in (raw.replace(m.UUID.encode(),b'foreign'),raw.replace(b'type=ethernet',b'type=wifi'),raw.replace(b'method=auto',b'method=manual'),raw.replace(b'interface-name=eth0',b'interface-name=eth0\nstable-id=${BOOT}')):
            with self.assertRaises(ValueError):m.profile(bad)
        with self.assertRaisesRegex(ValueError,'parse failed'):m.profile(b'SECRET INVALID')

    def test_nonroot_submits_no_command_or_write(self):
        h=types.SimpleNamespace(sha=lambda raw:'digest',encoded=lambda obj:b'{}',bounded=None)
        with patch.object(m.os,'geteuid',return_value=1000),patch.object(m,'write') as write:
            result=m.apply({'operation_id':'fixture','hostname':'master','boot_id':'boot'},h)
        self.assertFalse(result['write_intent']);self.assertFalse(result['persisted']);write.assert_not_called()

    def test_review_names_mutation_and_hold_boundary(self):
        raw=m.review({'operation_id':'fixture','expires_epoch':100})
        self.assertIn('connection modify',raw);self.assertIn('persistent network',raw)
        self.assertIn('no automatic',raw);self.assertIn('separately reviewed',raw)


if __name__=='__main__':unittest.main()
