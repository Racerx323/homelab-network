#!/usr/bin/env python3
"""Narrow, additive IPv6 NTP firewall transaction; no host address rewriting."""
import copy
import json


def require(condition, message):
    if not condition:
        raise ValueError(message)


def body(policy):
    """Controller-assigned position/identity are not writable policy fields."""
    return {k: v for k, v in policy.items() if k not in ('id', 'index', 'metadata')}


def canonical(policies):
    return {p['id']: {k: v for k, v in p.items() if k != 'index'} for p in policies}


def candidates(spec):
    return [{
        'name': spec['operation_id'] + '-' + protocol.lower(),
        'description': 'Managed operation ' + spec['operation_id'],
        'enabled': False,
        'loggingEnabled': False,
        'action': {'type': 'ALLOW', 'allowReturnTraffic': False},
        'source': {'zoneId': spec['source_zone'], 'trafficFilter': {
            'type': 'MAC_ADDRESS', 'macAddressFilter': {'macAddresses': [spec['mac']]}}},
        'destination': {'zoneId': spec['destination_zone'], 'trafficFilter': {
            'type': 'PORT', 'portFilter': {'type': 'PORTS', 'matchOpposite': False,
                                        'items': [{'type': 'PORT_NUMBER', 'value': port}]}}},
        'ipProtocolScope': {'ipVersion': 'IPV6', 'protocolFilter': {
            'type': 'NAMED_PROTOCOL', 'protocol': {'name': protocol}, 'matchOpposite': False}},
    } for protocol, port in (('UDP', 123), ('TCP', 4460))]


def equivalent(actual, wanted):
    # The API may expose this telemetry default; it does not expand the match.
    actual = body(actual)
    actual.pop('reportFlowEnabled', None)
    for key in ('connectionStateFilter', 'schedule', 'ipsecFilter'):
        if actual.get(key) is None:
            actual.pop(key, None)
    return actual == wanted


def owned(snapshot, spec):
    found = []
    for wanted in candidates(spec):
        rows = [p for p in snapshot['policies'] if p['name'] == wanted['name']]
        require(len(rows) <= 1, 'duplicate operation policy name')
        if rows:
            p = rows[0]
            desired = dict(wanted, enabled=p['enabled'])
            require(type(p['enabled']) is bool and equivalent(p, desired),
                    'operation policy content drift')
            require(p['metadata']['origin'] == 'USER_DEFINED', 'policy origin drift')
            found.append(p)
    return found


def unchanged(snapshot, baseline, spec):
    additions = owned(snapshot, spec)
    ids = {p['id'] for p in additions}
    require(canonical([p for p in snapshot['policies'] if p['id'] not in ids]) ==
            canonical(baseline['policies']), 'existing policies changed')
    for key in ('lists', 'networks', 'zones', 'version', 'reverse_order'):
        require(snapshot[key] == baseline[key], key + ' changed')
    order = snapshot['order']['orderedFirewallPolicyIds']
    original = baseline['order']['orderedFirewallPolicyIds']
    require(set(order) == {'beforeSystemDefined', 'afterSystemDefined'}, 'ordering shape')
    for group in order:
        require([v for v in order[group] if v not in ids] == original[group],
                'existing policy ordering changed')
    all_ids = order['beforeSystemDefined'] + order['afterSystemDefined']
    require(len(all_ids) == len(set(all_ids)), 'duplicate ordered policy')
    require(set(all_ids) == set(original['beforeSystemDefined'] +
                               original['afterSystemDefined']) | ids, 'ordering coverage')
    return additions


def proposed_order(baseline, spec, policies):
    order = copy.deepcopy(baseline['order'])
    before = order['orderedFirewallPolicyIds']['beforeSystemDefined']
    require(spec['reject_id'] in before, 'reject ordering missing')
    index = before.index(spec['reject_id'])
    before[index:index] = [p['id'] for p in policies]
    return order


def accepted(snapshot, baseline, spec):
    additions = unchanged(snapshot, baseline, spec)
    require(len(additions) == 2 and all(p['enabled'] for p in additions), 'enable readback')
    require(snapshot['order'] == proposed_order(baseline, spec, additions), 'final ordering')


def apply(api, baseline, spec, checkpoint):
    current = api.snapshot()
    require(not unchanged(current, baseline, spec), 'operation already has policies')
    checkpoint('before.json', current)
    for number, candidate in enumerate(candidates(spec), 1):
        checkpoint(candidate['name'] + '-create-intent.json', candidate)
        api.create(candidate)  # Never retry a POST after an ambiguous response.
        current = api.snapshot()
        created = unchanged(current, baseline, spec)
        require(len(created) == number and all(p['enabled'] is False for p in created),
                'disabled create readback failed')
    additions = owned(current, spec)
    require(len(additions) == 2 and not any(p['enabled'] for p in additions),
            'two disabled candidates required')
    order = proposed_order(baseline, spec, additions)
    checkpoint('order-intent.json', order)
    api.order(order)
    for candidate in additions:
        current = api.snapshot()
        unchanged(current, baseline, spec)
        require(current['order'] == order, 'candidate order not applied')
        desired = dict(body(candidate), enabled=True)
        desired.pop('reportFlowEnabled', None)
        checkpoint(candidate['name'] + '-enable-intent.json', desired)
        api.update(candidate['id'], desired)
        current = api.snapshot()
        live = unchanged(current, baseline, spec)
        require(any(p['id'] == candidate['id'] and p['enabled'] is True for p in live),
                'individual enable readback failed')
    current = api.snapshot()
    accepted(current, baseline, spec)
    checkpoint('applied.json', current)


def recover(api, baseline, spec, checkpoint):
    """Only remove exact operation-owned additions; never overwrite other edits."""
    current = api.snapshot()
    additions = unchanged(current, baseline, spec)
    for policy in additions:
        # Re-observe after each mutation; an unexpected operator edit holds recovery.
        current = api.snapshot()
        live = unchanged(current, baseline, spec)
        matches = [p for p in live if p['id'] == policy['id']]
        require(len(matches) == 1, 'recovery policy identity changed')
        policy = matches[0]
        if policy['enabled']:
            desired = dict(body(policy), enabled=False)
            desired.pop('reportFlowEnabled', None)
            checkpoint(policy['name'] + '-disable-intent.json', desired)
            api.update(policy['id'], desired)
        current = api.snapshot()
        live = unchanged(current, baseline, spec)
        policy = next(p for p in live if p['id'] == policy['id'])
        require(policy['enabled'] is False, 'disable readback failed')
        checkpoint(policy['name'] + '-delete-intent.json', {'id': policy['id']})
        api.delete(policy['id'])
    current = api.snapshot()
    require(not unchanged(current, baseline, spec), 'recovery additions remain')
    require(current['order'] == baseline['order'], 'original ordering not restored')
    checkpoint('recovered.json', current)


def from_report(report, spec):
    require(report['phase'] == 'captured', 'complete controller report required')
    records = report['records']
    base = '/proxy/network/integration/v1/sites/' + spec['site_id']

    def one(path):
        rows = [r['body'] for r in records if r['path'] == path]
        require(len(rows) == 1, 'missing or duplicate controller record')
        return rows[0]

    def pages(suffix):
        rows = [r['body'] for r in records if r['path'].startswith(base + suffix + '?limit=')]
        require(bool(rows), 'missing paginated record')
        return sorted([x for r in rows for x in r['data']], key=lambda x: x['id'])

    return {'policies': pages('/firewall/policies'), 'networks': pages('/networks'),
            'zones': pages('/firewall/zones'),
            'version': one('/proxy/network/integration/v1/info'),
            'order': one(base + '/firewall/policies/ordering?' + spec['order_query']),
            'reverse_order': one(base + '/firewall/policies/ordering?' + spec['reverse_query']),
            'lists': {r['body']['id']: r['body'] for r in records
                      if r['path'].startswith(base + '/traffic-matching-lists/')}}
