#!/usr/bin/python3
"""Seal or execute a GET-only Munin master DHCP-reservation inspection."""
import argparse
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import stat
import subprocess
import tarfile
import time

HERE=Path(__file__).resolve().parent
HOST='udmbt.local.theama.co'
ADDRESS='10.1.0.1'
MAC='2c:cf:67:ee:53:bd'
CLIENT='/proxy/network/integration/v1/sites/88f7af54-98f8-306a-a1c7-c9349722b1f6/clients/25310afd-88f4-3695-9ba6-3e566a0eb3ef'
RESERVATIONS='/proxy/network/api/s/default/rest/user'
CLIENTS='/proxy/network/api/s/default/stat/sta'
NETWORKS='/proxy/network/api/s/default/rest/networkconf'
DESIRED4='10.1.3.83'
DESIRED6='fd36:5aa8:6971:1::83'
SOURCES={'runner.py':Path(__file__).resolve(),'tests.py':HERE/'tests/test_munin_source.py',
         'access.md':HERE.parent/'UNIFI_ACCESS.md',
         'ipam.yaml':HERE.parent.parent/'ipam/hosts.yaml'}


class InspectionError(ValueError):
    """A fixed, non-secret validation reason safe to retain."""


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def private(path):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or s.st_size>1048576:
        raise InspectionError('private regular input required')
    return path.read_bytes()


def write(path,raw):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())


class API:
    def __init__(self,mode='reservation'):
        if mode not in ('reservation','conflicts'):raise InspectionError('inspection mode')
        self.paths=('/',CLIENT,RESERVATIONS,CLIENTS,NETWORKS) if mode=='conflicts' else ('/',CLIENT,RESERVATIONS)
        self.key=None;self.context=ssl.create_default_context();self.count=0
        self.deadline=time.monotonic()+90

    def request(self,method,path):
        # No arbitrary URL, redirect following, payload, or write method exists.
        if method!='GET' or path not in self.paths:raise InspectionError('GET-only fixed scope')
        self.count+=1
        if self.count>len(self.paths) or time.monotonic()>self.deadline:raise InspectionError('request/time bound')
        if path!='/' and not self.key:raise InspectionError('authentication required')
        connection=http.client.HTTPSConnection(HOST,timeout=10,context=self.context)
        raw=socket.create_connection((ADDRESS,443),timeout=10)
        try:
            connection.sock=self.context.wrap_socket(raw,server_hostname=HOST)
            headers={'Accept':'application/json'}
            if path!='/':headers['X-API-KEY']=self.key
            connection.request('GET',path,headers=headers)
            response=connection.getresponse();body=response.read(2*1024*1024+1)
            if len(body)>2*1024*1024:raise InspectionError('response bound')
            if path=='/':
                if response.status not in (200,301,302,303,307,308):raise InspectionError('TLS precheck HTTP '+str(response.status))
                return None
            if response.status!=200:raise InspectionError('GET HTTP '+str(response.status))
            if self.key.encode() in body:raise InspectionError('credential reflected')
            return json.loads(body)
        finally:connection.close();raw.close()

    def authenticate(self):
        addresses={x[4][0] for x in socket.getaddrinfo(HOST,443,socket.AF_INET,socket.SOCK_STREAM)}
        if addresses!={ADDRESS}:raise InspectionError('controller DNS drift')
        self.request('GET','/')
        p=subprocess.run(['doppler','secrets','get','AUDIT_LOCAL','--project','homelab-dev',
                          '--config','prd_unifi','--plain','--no-check-version'],capture_output=True,timeout=30)
        if p.returncode:raise InspectionError('credential retrieval failed')
        self.key=p.stdout.decode().strip()
        if not self.key or '\n' in self.key or '\r' in self.key:raise InspectionError('credential shape')


def reservation(value):
    if not isinstance(value,dict) or value.get('meta',{}).get('rc')!='ok':raise InspectionError('legacy reservation response unsupported')
    rows=value.get('data')
    if not isinstance(rows,list) or len(rows)>1000:raise InspectionError('reservation collection bound')
    matches=[r for r in rows if isinstance(r,dict) and r.get('mac','').lower()==MAC]
    if len(matches)!=1:raise InspectionError('master reservation missing or ambiguous')
    row=matches[0];enabled=row.get('use_fixedip');address=row.get('fixed_ip')
    if enabled is not None and type(enabled) is not bool:raise InspectionError('reservation flag shape')
    if address is not None:address=str(ipaddress.IPv4Address(address))
    return {'mac':MAC,'use_fixedip':enabled,'fixed_ip':address,
            'matches_observed_source':enabled is True and address=='10.1.3.83'}


def legacy_rows(value):
    if not isinstance(value,dict) or value.get('meta',{}).get('rc')!='ok':raise InspectionError('legacy response unsupported')
    rows=value.get('data')
    if not isinstance(rows,list) or len(rows)>1000 or not all(isinstance(r,dict) for r in rows):
        raise InspectionError('controller collection shape/bound')
    return rows


def address_evidence(rows,label):
    fields=('ip','fixed_ip','ipv6_address','ipv6_addresses','fixed_ipv6','ipv6','ipAddresses')
    result={'source':label,'rows_examined':len(rows),'ipv6_field_rows':0,'matches':[]}
    for row in rows:
        if any(k in row for k in fields if k not in ('ip','fixed_ip')):result['ipv6_field_rows']+=1
        values=[]
        for field in fields:
            value=row.get(field)
            if isinstance(value,str):values.append(value)
            elif isinstance(value,list) and len(value)<=128:
                for v in value:
                    if isinstance(v,str):values.append(v)
                    elif isinstance(v,dict):values.extend(v[k] for k in ('address','ipAddress') if isinstance(v.get(k),str))
            elif isinstance(value,list):raise InspectionError('client address bound')
        addresses=set()
        for value in values:
            try:addresses.add(str(ipaddress.ip_interface(value).ip))
            except ValueError:continue
        for address in (DESIRED4,DESIRED6):
            if address in addresses:
                owner=row.get('mac',row.get('macAddress',''))
                owner=owner.lower() if isinstance(owner,str) else ''
                # Export only relevant ownership classification, never raw clients.
                result['matches'].append({'address':address,'owner':'master' if owner==MAC else 'other_or_unknown'})
    return result


def network_evidence(rows):
    selected=[]
    for row in rows:
        try:subnet=ipaddress.ip_network(row.get('ip_subnet',''),strict=False)
        except (ValueError,TypeError):continue
        if subnet.version!=4 or ipaddress.ip_address(DESIRED4) not in subnet:continue
        item={'ipv4_subnet':str(subnet),'advertised_ipv6_prefixes':[],'ipv6_configuration_fields_present':False}
        for key in ('ipv6_subnet','ipv6_static_subnet','ipv6_prefix'):
            if key in row:item['ipv6_configuration_fields_present']=True
            try:prefix=ipaddress.ip_network(row.get(key,''),strict=False)
            except (ValueError,TypeError):continue
            if prefix.version==6:item['advertised_ipv6_prefixes'].append(str(prefix))
        selected.append(item)
    return selected


def collect(api,mode='reservation'):
    api.authenticate()
    client=api.request('GET',CLIENT)
    if not isinstance(client,dict) or client.get('macAddress','').lower()!=MAC:raise InspectionError('integration client MAC drift')
    registry=api.request('GET',RESERVATIONS)
    result={'client_mac':MAC,'reservation':reservation(registry),
            'ipv6_persistence_accepted':False,'network_mutation':False}
    if mode=='conflicts':
        configured=address_evidence(legacy_rows(registry),'configured_clients')
        active=address_evidence(legacy_rows(api.request('GET',CLIENTS)),'active_clients')
        result.update(address_evidence=[configured,active],
                      matching_networks=network_evidence(legacy_rows(api.request('GET',NETWORKS))),
                      reported_conflict=any(x['owner']!='master' for collection in (configured,active) for x in collection['matches']),
                      address_available_proven=False,ipv6_visibility_complete=False)
    return result


def review(spec):
    if spec.get('mode')=='conflicts':
        return f'''# GET-only static master address-conflict review

Operation {spec['operation_id']}; expires epoch {spec['expires_epoch']}.
Target https://{HOST}, pinned IPv4 {ADDRESS}, normal TLS chain/FQDN validation.
Desired host allocations: {DESIRED4} and {DESIRED6}; master MAC {MAC}.

Exactly five GETs: unauthenticated / for DNS/TLS precheck, fixed integration
master detail, legacy configured-client registry, active-client collection and
network definitions. These are the only permitted paths; no redirects/writes:

```text
{CLIENT}
{RESERVATIONS}
{CLIENTS}
{NETWORKS}
```

Verify target MAC and existing reservation. In memory examine only fixed address
fields for either desired address; persist counts and master/other-or-unknown
ownership classification. For IPv4 subnets containing the desired address,
export typed IPv4 subnet and selected IPv6 prefix fields only. Discard names,
raw clients/config, credentials and unrelated allocations. Each response is at
most 2 MiB/1000 records. Unsupported endpoint/schema fails without alternatives.
Incomplete IPv6 fields, offline/static hosts and passive visibility mean even
zero reported conflicts cannot prove address availability. Future authorized DAD
and guarded activation remain required; no address availability is accepted here.

Retrieve AUDIT_LOCAL through the canonical Doppler reference after DNS/TLS
validation, in memory only. GET-only code constrains this write-capable credential.
No SSH, probes, profile/DHCP/RA/firewall/DNS change, containers, checkpoint, services,
notifications or reboot. Approximately 120 seconds total; no automatic retries.
Failure consumes the stage. No persistent mutation needs restoration. Source,
tests, access procedure and IPAM are sealed; preparation contacts no controller.
After approval of the exact inspection.tar SHA-256, from homelab-network:

```text
python3 -I -B Ubiquiti/ntp-ipv6/inspect-munin-source.py execute --directory OUTPUT --sha256 APPROVED_SHA256
```
'''
    return f'''# Munin master reservation inspection

Operation {spec['operation_id']}; expires epoch {spec['expires_epoch']}.
Target https://{HOST}, pinned IPv4 {ADDRESS}; TLS chain and FQDN verification required.
Preserve current master networking. Inspect only the existing reservation for
svmf.local.theama.co, MAC {MAC}, observed route source 10.1.3.83.

Code permits exactly three GET requests: unauthenticated / for TLS precheck,
the fixed integration client detail below, then the fixed legacy reservation
collection. No redirects are followed; no login POST or other write exists.

```text
{CLIENT}
{RESERVATIONS}
```

The integration endpoint was observed in retained controller evidence. The legacy
reservation GET is not yet qualified with this credential/controller; unsupported
HTTP/schema, missing or duplicate MAC, or absent reservation fields stays a gap.
Do not substitute another endpoint or infer a reservation from a current address.
The in-memory response is bounded to 2 MiB and 1000 reservation records. Persist
only this MAC, Boolean reservation flag, fixed IPv4 and source-match result;
discard other clients and raw responses. Never retain API key or Doppler stderr.

Verify DNS and TLS before retrieving AUDIT_LOCAL in memory through the canonical
Doppler reference. That credential has write capability; the runner enforces
GET-only access. Request/time limits are three GETs and approximately 120 seconds
including credential retrieval. No SSH, DHCP renewal, network/profile/allowlist
change, package action, polling or notification. Access/audit metadata may change.
No persistent mutation needs rollback. Errors consume this single-use stage;
inspect evidence before any newly sealed attempt. IPv6 stability is a separate
master-local follow-up, not established by reservation results.

After approval of sealing.json's SHA-256, from homelab-network:

```text
python3 -I -B Ubiquiti/ntp-ipv6/inspect-munin-source.py execute --directory OUTPUT --sha256 APPROVED_SHA256
```
'''


def seal(directory,mode='reservation'):
    if mode not in ('reservation','conflicts'):raise InspectionError('inspection mode')
    now=int(time.time());spec={'operation_id':directory.name,'prepared_epoch':now,'expires_epoch':now+86400,'mode':mode}
    files={n:p.read_bytes() for n,p in SOURCES.items()}
    spec['members']={n:sha(v) for n,v in files.items()}
    files.update({'spec.json':encoded(spec),'review.md':review(spec).encode()})
    os.umask(0o077);directory.mkdir(mode=0o700)
    for n,v in files.items():write(directory/n,v)
    with tarfile.open(directory/'inspection.tar','w') as t:
        for n,v in sorted(files.items()):
            member=tarfile.TarInfo(n);member.mode=0o600;member.size=len(v);t.addfile(member,io.BytesIO(v))
    digest=sha((directory/'inspection.tar').read_bytes());prepare(directory,digest)
    result={'sha256':digest,'target_contact':False,'expires_epoch':spec['expires_epoch']}
    write(directory/'sealing.json',encoded(result));return result


def prepare(directory,digest):
    raw=private(directory/'inspection.tar')
    if sha(raw)!=digest:raise InspectionError('archive digest mismatch')
    with tarfile.open(fileobj=io.BytesIO(raw)) as t:
        members=t.getmembers();expected=set(SOURCES)|{'spec.json','review.md'}
        if len(members)!=len(expected) or {m.name for m in members}!=expected or any(not m.isfile() or m.size>1048576 for m in members):
            raise InspectionError('closed regular archive required')
        files={m.name:t.extractfile(m).read() for m in members}
    spec=json.loads(files['spec.json'])
    if spec.get('mode') not in ('reservation','conflicts') or not 0<spec['expires_epoch']-spec['prepared_epoch']<=86400 or not spec['prepared_epoch']-300<=time.time()<spec['expires_epoch']-120:
        raise InspectionError('approval window expired')
    if spec['members']!={n:sha(files[n]) for n in SOURCES} or files['review.md']!=review(spec).encode():raise InspectionError('scope/member binding')
    if any(files[n]!=p.read_bytes() for n,p in SOURCES.items()):raise InspectionError('source drift')
    if any(private(directory/n)!=files[n] for n in files):raise InspectionError('review input drift')
    return spec


def execute(directory,digest):
    spec=prepare(directory,digest)
    write(directory/'execution.json',encoded({'bundle_sha256':digest,'epoch':int(time.time())}))
    result={'operation_id':spec['operation_id'],'bundle_sha256':digest,'capture_complete':False}
    def expired(signum,frame):raise InspectionError('inspection deadline exceeded')
    old_handler=signal.signal(signal.SIGALRM,expired);signal.alarm(120)
    try:result.update(collect(API(spec['mode']),spec['mode']),capture_complete=True)
    except Exception as error:
        # Network/credential exception messages may contain sensitive fragments.
        result.update(error_type=type(error).__name__,
                      error=str(error) if isinstance(error,InspectionError) else 'inspection failed; no automatic retry')
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,old_handler)
    write(directory/'result.json',encoded(result));return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    a=sub.add_parser('seal');a.add_argument('--directory',type=Path,required=True);a.add_argument('--mode',choices=('reservation','conflicts'),default='reservation')
    a=sub.add_parser('execute');a.add_argument('--directory',type=Path,required=True);a.add_argument('--sha256',required=True)
    args=parser.parse_args();os.umask(0o077)
    result=seal(args.directory,args.mode) if args.action=='seal' else execute(args.directory,args.sha256)
    print(json.dumps(result))
    if args.action=='execute' and not result['capture_complete']:raise SystemExit(1)
