#!/usr/bin/env python3
"""Offline acceptance, lost-response and recovery boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p, r = load('policy'), load('run')
SPEC = {'operation_id': 'ntp-ipv6-permit-20261013-v1', 'source_zone': 'lan',
        'destination_zone': 'wan', 'mac': '02:00:00:00:00:01', 'reject_id': 'reject', 'site_id': 'site'}


def baseline():
    return {'policies': [{'id': 'reject', 'name': 'reject', 'index': 10,
                          'enabled': True, 'action': {'type': 'REJECT'}}],
            'order': {'orderedFirewallPolicyIds': {'beforeSystemDefined': ['reject'],
                                                  'afterSystemDefined': []}},
            'reverse_order': {}, 'lists': {}, 'zones': [], 'networks': [], 'version': {}}


class Fake:
    def __init__(self):
        self.state = baseline()
        self.calls = []
        self.lose_create = False
        self.lose_update = False
        self.lose_delete = False

    def authenticate(self):
        pass

    def snapshot(self):
        return copy.deepcopy(self.state)

    def create(self, wanted):
        self.calls.append('create')
        row = dict(copy.deepcopy(wanted), id=str(uuid.uuid4()), index=99,
                   metadata={'origin': 'USER_DEFINED'}, reportFlowEnabled=True)
        self.state['policies'].append(row)
        self.state['order']['orderedFirewallPolicyIds']['beforeSystemDefined'].append(row['id'])
        if self.lose_create:
            raise TimeoutError('response lost after create')

    def order(self, order):
        self.calls.append('order')
        self.state['order'] = copy.deepcopy(order)

    def update(self, identifier, wanted):
        self.calls.append('update')
        row = next(x for x in self.state['policies'] if x['id'] == identifier)
        row.update(copy.deepcopy(wanted))
        if self.lose_update:
            self.lose_update = False
            raise TimeoutError('response lost after enable')

    def delete(self, identifier):
        self.calls.append('delete')
        self.state['policies'] = [x for x in self.state['policies'] if x['id'] != identifier]
        for group in self.state['order']['orderedFirewallPolicyIds'].values():
            if identifier in group:
                group.remove(identifier)
        if self.lose_delete:
            self.lose_delete = False
            raise TimeoutError('response lost after deletion')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.api = Fake()
        self.events = {}

    def checkpoint(self, name, value):
        self.assertNotIn(name, self.events)
        self.events[name] = value

    def apply(self):
        p.apply(self.api, baseline(), SPEC, self.checkpoint)

    def recover(self):
        p.recover(self.api, baseline(), SPEC, self.checkpoint)

    def test_exact_family_source_and_ports(self):
        rows = p.candidates(SPEC)
        self.assertEqual(len(rows), 2)
        self.assertEqual([x['ipProtocolScope']['protocolFilter']['protocol']['name'] for x in rows], ['UDP', 'TCP'])
        self.assertEqual([x['destination']['trafficFilter']['portFilter']['items'][0]['value'] for x in rows], [123, 4460])
        for row in rows:
            self.assertFalse(row['enabled'])
            self.assertEqual(row['ipProtocolScope']['ipVersion'], 'IPV6')
            self.assertEqual(row['source']['trafficFilter'], {'type': 'MAC_ADDRESS',
                              'macAddressFilter': {'macAddresses': [SPEC['mac']]}})
            self.assertFalse(row['action']['allowReturnTraffic'])

    def test_apply_accept_and_recover(self):
        self.apply()
        p.accepted(self.api.snapshot(), baseline(), SPEC)
        self.assertEqual(self.api.calls, ['create', 'create', 'order', 'update', 'update'])
        self.recover()
        self.assertEqual(self.api.snapshot(), baseline())

    def test_ambiguous_create_discovered_without_repost(self):
        self.api.lose_create = True
        with self.assertRaises(TimeoutError):
            self.apply()
        self.recover()
        self.assertEqual(self.api.calls.count('create'), 1)
        self.assertEqual(self.api.snapshot(), baseline())

    def test_lost_enable_recovers(self):
        self.api.lose_update = True
        with self.assertRaises(TimeoutError):
            self.apply()
        self.recover()
        self.assertEqual(self.api.snapshot(), baseline())

    def test_lost_delete_continuation_does_not_redelete(self):
        self.apply()
        self.api.lose_delete = True
        with self.assertRaises(TimeoutError):
            self.recover()
        self.events = {}
        self.recover()
        self.assertEqual(self.api.calls.count('delete'), 2)
        self.assertEqual(self.api.snapshot(), baseline())

    def test_existing_policy_drift_blocks_before_write(self):
        self.api.state['policies'][0]['enabled'] = False
        with self.assertRaisesRegex(ValueError, 'existing policies'):
            self.apply()
        self.assertEqual(self.api.calls, [])

    def test_unrelated_change_blocks_recovery(self):
        self.apply()
        count = len(self.api.calls)
        self.api.state['policies'][0]['enabled'] = False
        with self.assertRaises(ValueError):
            self.recover()
        self.assertEqual(len(self.api.calls), count)

    def test_broadened_owned_match_never_deleted(self):
        self.apply()
        self.api.state['policies'][1]['source']['trafficFilter'] = {'type': 'NETWORK'}
        with self.assertRaisesRegex(ValueError, 'content drift'):
            self.recover()
        self.assertNotIn('delete', self.api.calls)

    def test_duplicate_name_rejected(self):
        self.apply()
        self.api.state['policies'].append(copy.deepcopy(self.api.state['policies'][1]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            p.accepted(self.api.snapshot(), baseline(), SPEC)

    def test_disabled_or_reordered_final_rule_fails(self):
        self.apply()
        self.api.state['policies'][1]['enabled'] = False
        with self.assertRaises(ValueError):
            p.accepted(self.api.snapshot(), baseline(), SPEC)
        self.api.state['policies'][1]['enabled'] = True
        self.api.state['order']['orderedFirewallPolicyIds']['beforeSystemDefined'].reverse()
        with self.assertRaises(ValueError):
            p.accepted(self.api.snapshot(), baseline(), SPEC)

    def test_schema_unknown_field_not_ignored(self):
        self.apply()
        self.api.state['policies'][1]['unknownMatch'] = 'ANY'
        with self.assertRaises(ValueError):
            self.recover()

    def test_nullable_api_defaults(self):
        wanted = p.candidates(SPEC)[0]
        actual = dict(wanted, schedule=None, ipsecFilter=None, connectionStateFilter=None)
        self.assertTrue(p.equivalent(actual, wanted))

    def test_registration_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'intent.json'
            r.write(path, {'once': True})
            with self.assertRaises(FileExistsError):
                r.write(path, {'again': True})

    def test_symlink_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            r.write(path / 'regular', b'test')
            (path / 'link').symlink_to(path / 'regular')
            with self.assertRaises(ValueError):
                r.private(path / 'link')

    def test_version_drift_rejected(self):
        self.api.state['version'] = {'applicationVersion': 'different'}
        with self.assertRaisesRegex(ValueError, 'version changed'):
            self.apply()

    def test_auth_failure_never_gets_secret(self):
        api = r.API(dict(SPEC, controller='controller.invalid', controller_ipv4='192.0.2.1'), baseline())
        with patch.object(r.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('192.0.2.1', 443))]), \
                patch.object(api, 'request', side_effect=ValueError('TLS failure')), \
                patch.object(r.subprocess, 'run') as secret:
            with self.assertRaises(ValueError):
                api.authenticate()
            secret.assert_not_called()

    def test_noop_create_stops_before_second_post(self):
        with patch.object(self.api, 'create') as create:
            with self.assertRaisesRegex(ValueError, 'disabled create'):
                self.apply()
            self.assertEqual(create.call_count, 1)

    def test_failed_postchange_probes_trigger_automatic_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'before').mkdir()
            r.write(root / 'before/unifi-report.json', {})
            spec = dict(SPEC, execution_inputs={}, prepared_epoch=int(time.time()),
                        start_before_epoch=int(time.time()) + 300)
            files = {'spec.json': r.encoded(spec), 'baseline.json': r.encoded(baseline()), 'policy.py': b'fixture'}
            labels = []

            def capture(directory, spec, label, checkpoint):
                labels.append(label)
                if label == 'after':
                    raise ValueError('TCP refusal')

            with patch.object(r, 'unpack', return_value=files), \
                    patch.object(r, 'module', return_value=p), \
                    patch.object(p, 'from_report', return_value=baseline()), \
                    patch.object(r, 'API', return_value=self.api), \
                    patch.object(r, 'capture', side_effect=capture):
                result = r.execute(SimpleNamespace(bundle=root/'bundle.tar', sha256='fixture', mode='apply'))
            self.assertEqual(result['state'], 'recovered_after_failure')
            self.assertEqual(labels, ['before', 'after', 'recovery'])
            self.assertEqual(self.api.snapshot(), baseline())
            self.assertFalse((root / 'apply/accepted.json').exists())

    def test_archive_checksum_rejects_before_any_api(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bundle.tar'
            r.write(path, b'not an approved archive')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                r.unpack(path, '0' * 64)


if __name__ == '__main__':
    unittest.main()
