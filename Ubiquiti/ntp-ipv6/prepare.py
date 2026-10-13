#!/usr/bin/env python3
"""Bind accepted evidence, exact policies and fresh diagnostic bundles offline."""
import argparse
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

HERE = Path(__file__).resolve().parent


def load(name):
    s = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


r, p = load('run'), load('policy')


def prepare(args):
    r.require(re.fullmatch(r'ntp-ipv6-permit-[0-9]{8}-v[1-9][0-9]*', args.operation_id), 'operation ID')
    evidence = args.evidence.resolve()
    receipt = json.loads(r.private(evidence / 'inspection-acceptance.json'))
    raw = r.private(evidence / 'unifi-report.json')
    r.require(r.sha(raw) == receipt['controller']['report_sha256'] and
              receipt['controller']['state'] == 'captured' and
              receipt['node']['state'] == 'diagnostics_captured', 'accepted evidence required')
    report = json.loads(raw)
    result = json.loads(r.private(evidence / 'readback-1-0-result.json'))
    other = json.loads(r.private(evidence / 'readback-1-1-result.json'))
    r.require(result == other, 'matching accepted node evidence')
    node_raw = (json.dumps(result['result'], sort_keys=True) + '\n').encode()
    r.require(r.sha(node_raw) == receipt['node']['report_sha256'], 'accepted node report digest')
    old_spec = json.loads(r.private(evidence / 'spec.json'))
    r.require(r.sha(r.private(evidence / 'spec.json')) == receipt['node']['spec_sha256'] and
              old_spec['hostname'] == 'j2-svntp1', 'accepted target identity')
    r.require(r.sha(r.private(evidence / 'cutover-inspection.tar')) == receipt['bundle_sha256'],
              'accepted diagnostic archive digest')
    cleanup = json.loads(r.private(evidence / 'cleanup-0-result.json'))['result']
    r.require(cleanup['phase'] == 'cleaned' and cleanup['source_unchanged'] and
              cleanup['report_sha256'] == receipt['node']['report_sha256'], 'closed diagnostic required')
    raw_addresses = base64.b64decode(result['result']['evidence']['addresses.stdout']['base64'], validate=True)
    r.require(r.sha(raw_addresses) == result['result']['evidence']['addresses.stdout']['sha256'], 'address digest')
    nic = [x for x in json.loads(raw_addresses) if x['ifname'] == 'eth0']
    r.require(len(nic) == 1 and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', nic[0]['address']), 'Ethernet MAC')
    network = next(x for record in report['records'] if '/networks?' in record['path']
                   for x in record['body']['data'] if x['name'] == 'Default LAN')
    external = next(x for record in report['records'] if '/firewall/zones?' in record['path']
                    for x in record['body']['data'] if x['name'] == 'External')
    spec = {'schema': 1, 'operation_id': args.operation_id, 'hostname': 'j2-svntp1',
            'controller': 'udmbt.local.theama.co', 'controller_ipv4': '10.1.0.1',
            'site_id': report['site_id'], 'source_zone': network['zoneId'],
            'destination_zone': external['id'], 'network_id': network['id'], 'mac': nic[0]['address']}
    for key, source, dest in [('order_query', spec['source_zone'], spec['destination_zone']),
                              ('reverse_query', spec['destination_zone'], spec['source_zone'])]:
        spec[key] = 'sourceFirewallZoneId=' + source + '&destinationFirewallZoneId=' + dest
    baseline = p.from_report(report, spec)
    rejects = [x for x in baseline['policies'] if x['name'] == 'Reject NTP to WAN - Default LAN']
    r.require(len(rejects) == 1, 'unique reject required')
    reject = rejects[0]
    r.require(reject['enabled'] and reject['action']['type'] == 'REJECT' and
              reject['ipProtocolScope']['ipVersion'] == 'IPV4_AND_IPV6' and
              reject['source']['zoneId'] == spec['source_zone'] and
              reject['destination']['zoneId'] == spec['destination_zone'], 'reject scope')
    ports = baseline['lists'][reject['destination']['trafficFilter']['portFilter']['trafficMatchingListId']]
    r.require(ports['type'] == 'PORTS' and {x['value'] for x in ports['items']} == {123, 4460}, 'reject ports')
    spec['reject_id'] = reject['id']
    r.require(not p.owned(baseline, spec), 'operation names already present')
    r.require(any(x['action']['type'] == 'ALLOW' and
                  set(x.get('connectionStateFilter', [])) == {'ESTABLISHED', 'RELATED'} and
                  x['source']['zoneId'] == spec['destination_zone'] and
                  x['destination']['zoneId'] == spec['source_zone'] and x['enabled']
                  for x in baseline['policies']), 'return traffic rule required')
    spec['prepared_epoch'] = int(time.time())
    spec['ntp_repo'] = str(args.ntp_repo.resolve())
    spec['diagnostic_runner'] = str(args.ntp_repo.resolve() / 'ntpsec/scripts/run-nts-transport-inspection.py')
    spec['execution_inputs'] = {str(x.resolve()): r.sha(x.read_bytes())
                                for x in (args.ntp_repo / 'ntpsec/scripts').glob('*.py')}
    # Current sealed tool checks; no live contact occurs while sealing.
    args.output.mkdir(mode=0o700)
    spec['children'] = {}
    expiries = []
    for label in ('before', 'after', 'recovery'):
        folder = args.output / label
        command = ['/usr/bin/python3', '-I', '-B', spec['diagnostic_runner'], 'seal',
                   '--source-dir', str(args.source_dir.resolve()), '--source-sha256', args.source_sha256,
                   '--operation-id', args.operation_id + '-' + label, '--output', str(folder.resolve())]
        result = subprocess.run(command, capture_output=True, timeout=60, cwd=args.ntp_repo)
        r.require(result.returncode == 0, 'offline diagnostic seal failed')
        sealed = json.loads(result.stdout)
        spec['children'][label] = {'sha256': sealed['sha256']}
        expiries.append(sealed['expires_epoch'])
    spec['expires_epoch'] = min(expiries)
    spec['start_before_epoch'] = min(expiries) - 7200
    schema = args.openapi.read_bytes()
    api = json.loads(schema)
    r.require('put' in api['paths']['/v1/sites/{siteId}/firewall/policies/ordering'], 'ordering API contract')
    spec['api_schema_sha256'] = r.sha(schema)
    spec['evidence_sha256'] = {name: r.sha(r.private(evidence / name)) for name in
                              ('inspection-acceptance.json', 'unifi-report.json',
                               'readback-1-0-result.json', 'readback-1-1-result.json', 'cleanup-0-result.json')}
    docs = args.ntp_repo / 'ntpsec'
    files = {name: (HERE / name).read_bytes() for name in ('run.py', 'policy.py', 'prepare.py', 'README.md')}
    files.update({'tests.py': (HERE / 'tests/test_policy.py').read_bytes(),
                  'network-access.md': (HERE.parent / 'UNIFI_ACCESS.md').read_bytes(),
                  'architecture.md': (docs / 'docs/ntp-architecture-deployment-plan-v1.0.md').read_bytes(),
                  'operations.md': (docs / 'docs/OPERATIONS.md').read_bytes(),
                  'history.md': (docs / 'HISTORY.md').read_bytes(),
                  'api-schema.json': schema, 'spec.json': r.encoded(spec),
                  'baseline.json': r.encoded(baseline), 'candidates.json': r.encoded(p.candidates(spec))})
    review = f'''# IPv6 NTP permits: {args.operation_id}

Targets: **{spec['controller']}** and **j2-svntp1**. Automated API operation;
offline preparation only. Separate execution approval binds `bundle.tar` SHA-256.

Source: Ethernet MAC `{spec['mac']}` in the captured Default LAN source zone.
Add exactly two IPv6-only permits: UDP 123 and TCP 4460, destination External.
Create disabled, verify, insert immediately before `{spec['reject_id']}`, enable,
then require all 12 root/NTP-account IPv4/IPv6 TCP checks to connect. Preserve all
existing policies, lists, return rules and their relative order. No GUA list,
prefix updater, host networking change, broad LAN permit or service activation.

Run the sealed `before`, `after`, and conditional `recovery` diagnostic bundles
once each, including controller-first capture, dual-endpoint readback and cleanup.
Each allows at most 12 TCP connects (2 seconds each), 40 controller requests and
the bounds in its review. No UDP datagrams, TLS negotiation or clock writes.
Up to three numbered terminal readbacks per child are allowed after interrupted
retrieval; never repeat child start or controller capture. Child closure preserves
all evidence. The mutation client permits at most 240 requests and 64 MiB per
attempt, 2 MiB per response, 10-second socket waits and a 600-second API deadline.

Bind the source MAC and eth0 routes to fresh node evidence. Baseline API policy,
ordering, referenced lists, zones, networks and version must match before writes.
Every state check rejects unrelated changes. This is a sequence of checked API
calls, not an atomic controller transaction. No other administrator should edit
firewall policy during this window.

Recovery: on failure after possible mutation, discover exact operation-owned
objects (including a create whose response was lost), disable and delete only
those two objects, verify original policies/order and run the recovery capture.
One separate `recover` continuation is allowed after an interrupted/held apply.
Never replay create or overwrite unexpected policy changes. There is no independent
gateway timer: controller/workstation loss can leave the narrowly scoped permits
until the approved recovery continuation can reconnect. Preserve all receipts.
Conditional recovery stops on unrelated drift or inaccessible controller.

MAC matching avoids depending on a stored global address. Actual packet behavior
must pass the IPv6 checks; address/prefix rollover itself is not tested. A changed
NIC/MAC or routed topology needs a new review. UDP and authenticated NTS acceptance
remain in the final service cutover; this stage accepts policy and TCP only.

API contract: Ubiquiti Network v10.6.106 OpenAPI; captured controller version:
`{baseline['version'].get('applicationVersion')}`. Stop on unsupported schema/method;
do not try another API or authentication bypass. `AUDIT_LOCAL` is operator-confirmed
read/write; credentials stay in memory and outside archive/logs.

Start before epoch `{spec['start_before_epoch']}`; child start expiry
`{spec['expires_epoch']}`. The two-hour reserve covers bounded captures/recovery.
Command: `python3 -I -B {HERE / 'run.py'} --bundle {args.output.resolve() / 'bundle.tar'} --sha256 <approved-sha256> --mode apply`.
Conditional continuation uses the same command with `--mode recover`.
'''
    files['review.md'] = review.encode()
    files['manifest.json'] = r.encoded({name: r.sha(value) for name, value in files.items()})
    archive_path = args.output / 'bundle.tar'
    with tarfile.open(archive_path, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.mode, info.size, info.mtime = 0o600, len(raw), spec['prepared_epoch']
            archive.addfile(info, io.BytesIO(raw))
    digest = r.sha(archive_path.read_bytes())
    for name in ('review.md', 'spec.json', 'candidates.json'):
        r.write(args.output / name, files[name])
    r.write(args.output / 'sealing.json', {'sha256': digest, 'target_contact': False,
            'execution_authorized': False, 'start_before_epoch': spec['start_before_epoch'],
            'expires_epoch': spec['expires_epoch'], 'children': spec['children']})
    r.unpack(archive_path, digest)
    return {'bundle': str(archive_path), 'sha256': digest, 'target_contact': False}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('evidence', 'ntp-repo', 'source-dir', 'output', 'openapi'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--operation-id', required=True)
    print(json.dumps(prepare(parser.parse_args()), sort_keys=True))
