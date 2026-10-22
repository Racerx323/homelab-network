"""Persist the observed runtime profile without reapplying or activating it."""
import base64
import configparser
import json
import os
import re
from pathlib import Path
import socket
import stat

UUID='2cad90ef-210e-329a-bc55-9e23fa8160dd'
NAME='Wired connection 1'
RUNTIME=Path('/run/NetworkManager/system-connections/Wired connection 1.nmconnection')
PERSISTENT=Path('/etc/NetworkManager/system-connections/Wired connection 1.nmconnection')
IPV4='10.1.3.83'
ULA='fd36:5aa8:6971:1:2cf5:3096:c5f:3283'


def profile(raw):
    p=configparser.ConfigParser(interpolation=None)
    try:p.read_string(raw.decode())
    except Exception:raise ValueError('profile parse failed') from None
    if set(p.sections())-{'connection','ethernet','802-3-ethernet','ipv4','ipv6','proxy','.nmmeta'}:
        raise ValueError('unsupported profile section; do not persist under this scope')
    if p.get('connection','uuid',fallback=None)!=UUID:raise ValueError('profile UUID drift')
    if p.get('connection','id',fallback=None)!=NAME:raise ValueError('profile name drift')
    if p.get('connection','type',fallback=None) not in ('ethernet','802-3-ethernet'):raise ValueError('Ethernet profile required')
    if p.get('connection','interface-name',fallback=None)!='eth0':raise ValueError('profile interface drift')
    if p.get('ipv4','method',fallback=None)!='auto' or p.get('ipv6','method',fallback=None)!='auto':raise ValueError('address method drift')
    if p.get('connection','stable-id',fallback='').strip():raise ValueError('unexpected explicit stable-id')
    return p


def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())


def apply(spec,h):
    state={'operation_id':spec['operation_id'],'spec_sha256':h.sha(h.encoded(spec)),
           'capture_complete':False,'persisted':False,'write_intent':False,'running_network_unchanged':False}
    root=Path('/var/lib/munin-master-profile')/spec['operation_id'];root_created=False
    def command(argv):
        row=h.bounded(argv,timeout=25,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if row.get('error') or row.get('returncode')!=0:raise ValueError('bounded command failed: '+argv[0])
        return row['stdout']
    def snapshot():
        if os.geteuid()!=0 or socket.gethostname()!=spec['hostname'] or Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=spec['boot_id']:
            raise ValueError('master root/host/boot drift')
        if command(['/usr/bin/nmcli','--version']).strip()!='nmcli tool, version 1.42.4':raise ValueError('NetworkManager version drift')
        properties=command(['/usr/bin/nmcli','-g','connection.id,ipv6.addr-gen-mode','connection','show',UUID]).splitlines()
        if properties not in ([NAME,'default'],[NAME,'3']):raise ValueError('effective name/generation precondition drift')
        policy=configparser.ConfigParser(interpolation=None)
        try:policy.read_string(command(['/usr/sbin/NetworkManager','--print-config']))
        except Exception:raise ValueError('effective global policy unavailable') from None
        if any(key in ('ipv6.addr-gen-mode','connection.stable-id','stable-id')
               for section in policy.sections() for key in policy[section]):
            raise ValueError('global generation/stable-id override; do not persist under this scope')
        active=command(['/usr/bin/nmcli','-t','-f','UUID,DEVICE','connection','show','--active'])
        if [x for x in active.splitlines() if x.endswith(':eth0')]!=[UUID+':eth0']:raise ValueError('active profile drift')
        sources=[]
        for args,want in [(['-json','route','get','10.1.0.51'],IPV4),(['-6','-json','route','get','fd36:5aa8:6971:1::51'],ULA)]:
            rows=json.loads(command(['/usr/sbin/ip',*args]))
            if len(rows)!=1 or rows[0].get('dev')!='eth0' or rows[0].get('prefsrc')!=want:raise ValueError('route source drift')
            sources.append({'dev':'eth0','source':want})
        effective=command(['/usr/bin/nmcli','-m','multiline','-f','connection,802-3-ethernet,ipv4,ipv6,proxy','connection','show',UUID])
        manager=command(['/usr/bin/systemctl','show','NetworkManager.service','--property=MainPID,InvocationID,NRestarts,ActiveState,SubState'])
        identities=[]
        for name in ('/var/lib/NetworkManager/secret_key','/etc/machine-id'):
            path=Path(name);info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or any(p.is_symlink() for p in path.parents):raise ValueError('host identity file metadata drift')
            identities.append({'path':name,'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid,
                               'inode':info.st_ino,'size':info.st_size,'mtime_ns':info.st_mtime_ns})
        return {'active_uuid':UUID,'sources':sources,'effective_settings_sha256':h.sha(effective.encode()),
                'manager_identity':manager,'identity_file_metadata':identities}
    def filename():
        rows=command(['/usr/bin/nmcli','-t','-f','UUID,FILENAME','connection','show']).splitlines()
        matches=[x.partition(':')[2] for x in rows if x.partition(':')[0]==UUID]
        if len(matches)!=1:raise ValueError('profile filename selection')
        return matches[0]
    def read(path):
        row=h.file_record(path,content=True)
        if row.get('error') or row.get('missing') or row.get('changed_during_read') or row.get('uid')!=0 or row.get('mode',0)&0o077:
            raise ValueError('root-private regular profile required')
        raw=base64.b64decode(row.pop('base64'),validate=True);profile(raw);return raw,row
    try:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',spec['operation_id']):raise ValueError('operation identity')
        state['before']=snapshot()
        if filename()!=str(RUNTIME):raise ValueError('runtime profile path changed')
        raw,before=read(RUNTIME)
        if PERSISTENT.exists() or PERSISTENT.is_symlink():raise ValueError('persistent destination already exists')
        for path in (PERSISTENT.parent,*PERSISTENT.parent.parents):
            if path.is_symlink() or not path.is_dir() or path.stat().st_uid!=0 or path.stat().st_mode&0o022:
                raise ValueError('unsafe persistent destination ancestor')
        if any(p.is_symlink() for p in root.parents):raise ValueError('indirect backup ancestor')
        os.umask(0o077);root.parent.mkdir(mode=0o700,exist_ok=True)
        if root.parent.is_symlink() or root.parent.stat().st_uid!=0 or root.parent.stat().st_mode&0o077:raise ValueError('unsafe backup parent')
        root.mkdir(mode=0o700);root_created=True;write(root/'original-runtime-profile',raw)
        if read(RUNTIME)[0]!=raw or snapshot()!=state['before']:raise ValueError('pre-write drift')
        state.update(write_intent=True,backup=str(root/'original-runtime-profile'))
        write(root/'write-intent.json',h.encoded(state))
        command(['/usr/bin/nmcli','connection','modify',UUID,'connection.id',NAME,'ipv6.addr-gen-mode','default'])
        if filename()!=str(PERSISTENT):raise ValueError('persistent filename unexpected')
        saved,metadata=read(PERSISTENT);saved_profile=profile(saved)
        if saved_profile.get('ipv6','addr-gen-mode',fallback=None) not in ('3','default'):raise ValueError('explicit saved default generation required')
        state['persistent_file']={k:v for k,v in metadata.items() if k!='base64'}
        state['after']=snapshot()
        if state['after']!=state['before']:raise ValueError('effective settings/routing/manager identity changed')
        state.update(persisted=True,running_network_unchanged=True,capture_complete=True,
                     renewal_or_reboot_exercised=False,recovery='not-needed')
    except Exception as error:
        state.update(error=str(error),recovery='held; inspect saved profile and private backup before a separately approved restoration' if state['write_intent'] else 'no network write submitted')
    if root_created:write(root/'result.json',h.encoded(state))
    return state


def review(spec):
    return f'''# Preserve and persist the current master profile

Operation {spec['operation_id']}; expires epoch {spec['expires_epoch']}.
Target pi@10.1.3.83, pinned host key svmf.local.theama.co and accepted host/boot.
Network-owned action, transported by the NTP repository's sealed SSH controller.

The approved read-only inspection found this exact active profile under /run:
{RUNTIME}
UUID {UUID}; name {NAME}; automatic IPv4/IPv6 on eth0.
The installed NetworkManager version is 1.42.4. The existing IPv4 reservation
is verified. Save this same UUID and effective settings to persistent storage.

Preflight checks current host/boot, active UUID, both exact route sources,
root-private runtime profile and absent persistent destination. Validate Ethernet,
interface, UUID, name, automatic methods and unset stable-id. Fingerprint all
non-secret connection/Ethernet/IPv4/IPv6/proxy settings in memory. Retain only
digests, selected identities and metadata; no raw settings or credential output.
Read effective global NetworkManager configuration in memory before/after;
reject generation/stable-id overrides and discard the raw configuration.
Back up the original profile privately on the master before submitting one command:

```text
nmcli connection modify {UUID} connection.id 'Wired connection 1' ipv6.addr-gen-mode default
```

Both assigned property values match the current effective profile. Native
NetworkManager persistence is used; do not copy a keyfile behind the daemon.
No connection up/down, reapply, reload, restart, DHCP renewal or reboot occurs.
This changes saved state for later activations/boots. It is a persistent network
configuration mutation and needs its own exact-hash execution approval.

Acceptance requires the same UUID at {PERSISTENT}, root-private regular file,
explicit saved default generation, unchanged complete effective-settings digest,
both route sources and NetworkManager PID/invocation/restart state. Actual
renewal/reboot behavior remains a later observation, not an exercised test.

Before write submission, failure makes no network change. After submission,
failed acceptance holds with the private backup and intent/result retained;
there is no automatic delete/reload/reactivation or speculative rollback.
Restoring the runtime-only profile would require a separately reviewed native
NetworkManager settings restoration. Inspect live state before any retry.
This stage has parser/rejection and simulated backend success/drift tests;
native persistence is not yet
qualified on this live master. No other profile, service, allowlist, package,
node poll, master contact or notification is changed. Single-use local receipt.

After approval of the SHA-256 in sealing.json, from homelab-ntp:

```text
python3 -I -B ntpsec/scripts/run-munin-prerequisites.py execute --directory OUTPUT --sha256 APPROVED_SHA256
```
'''
