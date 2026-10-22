"""Native NetworkManager checkpoint primitive; no standalone deployment entrypoint.

An approved outer operation must own identity, backups, service acceptance,
independent connectivity and durable state. This module owns one device's native
checkpoint, configured settings, explicit commit and checked rollback only.
"""
import os
import re
import shlex
import subprocess
import time

BUS = '/usr/bin/busctl'
NM = '/usr/bin/nmcli'
SERVICE = 'org.freedesktop.NetworkManager'
PATH = '/org/freedesktop/NetworkManager'
LABELS = {'address4', 'address6', 'routes', 'dns', 'peer4', 'peer6', 'dad', 'service_continuity'}


def run(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=70,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if len(p.stdout) > 262144 or len(p.stderr) > 65536 or p.returncode:
        raise RuntimeError('native network command failed; retain private command evidence')
    return p.stdout.strip()


def object_path(raw, kind):
    fields = shlex.split(raw)
    if len(fields) != 2 or fields[0] != 'o' or not re.fullmatch(PATH+'/'+kind+r'/[0-9]+', fields[1]):
        raise ValueError('unexpected native object path')
    return fields[1]


class Checkpoint:
    def __init__(self, interface, uuid, settings, seconds=300, command=run):
        if (not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,14}', interface)
                or not re.fullmatch(r'[0-9a-f-]{36}', uuid)
                or not 5 <= seconds <= 300 or not settings
                or any(not re.fullmatch(r'(connection|ipv4|ipv6)\.[a-z0-9-]+', k)
                       or not isinstance(v, str) or '\x00' in v or '\n' in v for k, v in settings.items())):
            raise ValueError('bounded explicit checkpoint parameters required')
        self.interface = interface; self.uuid = uuid; self.settings = dict(settings)
        self.seconds = seconds; self.command = command; self.path = None; self.phase = 'new'

    def call(self, method, *args):
        return self.command([BUS, 'call', SERVICE, PATH, SERVICE, method, *args])

    def checkpoints(self):
        fields = shlex.split(self.command([BUS, 'get-property', SERVICE, PATH, SERVICE, 'Checkpoints']))
        if len(fields) < 2 or fields[0] != 'ao' or not fields[1].isdigit() or len(fields) != int(fields[1])+2:
            raise ValueError('checkpoint registry shape')
        return fields[2:]

    def snapshot(self):
        raw = self.command([NM, '-m', 'multiline', '-f', ','.join(sorted(self.settings)),
                            'connection', 'show', 'uuid', self.uuid])
        result = {}
        for line in raw.splitlines():
            key, sep, value = line.partition(':')
            if not sep or key not in self.settings or key in result:
                raise ValueError('selected profile shape')
            value = value.strip(); result[key] = '' if value == '--' else value
        if set(result) != set(self.settings):
            raise ValueError('selected profile incomplete')
        return result

    def begin(self):
        if os.geteuid() != 0 or self.phase != 'new' or self.checkpoints():
            raise ValueError('root, unused transaction and no competing checkpoints required')
        active = self.command([NM, '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active'])
        if [x for x in active.splitlines() if x.endswith(':'+self.interface)] != [self.uuid+':'+self.interface]:
            raise ValueError('active profile identity changed')
        self.original = self.snapshot()
        self.device = object_path(self.call('GetDeviceByIpIface', 's', self.interface), 'Devices')
        self.path = object_path(self.call('CheckpointCreate', 'aouu', '1', self.device, str(self.seconds), '0'), 'Checkpoint')
        self.deadline = time.monotonic()+self.seconds; self.phase = 'guarded'
        if self.path not in self.checkpoints():
            raise ValueError('checkpoint not armed')

    def apply(self):
        if self.phase != 'guarded' or self.path not in self.checkpoints():
            raise ValueError('native checkpoint required before profile write')
        argv = [NM, 'connection', 'modify', 'uuid', self.uuid]
        for key, value in self.settings.items():
            argv.extend([key, value])
        self.command(argv)
        self.command([NM, '--wait', '60', 'connection', 'up', 'uuid', self.uuid, 'ifname', self.interface])
        if self.snapshot() != self.settings:
            raise ValueError('persistent settings readback mismatch')
        self.phase = 'awaiting_confirmation'

    def commit(self, acceptance):
        if self.phase != 'awaiting_confirmation' or time.monotonic()+max(1, self.seconds/10) >= self.deadline:
            raise ValueError('confirmation phase or reserve failed')
        # The outer operation supplies actual independent acceptance, not labels
        # fabricated from command return codes. It must be sealed and qualified.
        checks = acceptance()
        if set(checks) != LABELS or any(value is not True for value in checks.values()):
            raise ValueError('complete independent acceptance required')
        if self.path not in self.checkpoints() or self.snapshot() != self.settings:
            raise ValueError('guard or settings changed before confirmation')
        self.call('CheckpointDestroy', 'o', self.path)
        if self.path in self.checkpoints():
            raise ValueError('checkpoint destruction not verified')
        self.phase = 'committed'

    def rollback(self):
        if self.phase in ('new', 'committed', 'rolled_back') or not self.path:
            raise ValueError('owned active checkpoint required')
        if self.path in self.checkpoints():
            fields = shlex.split(self.call('CheckpointRollback', 'o', self.path))
            if fields != ['a{su}', '1', self.device, '0']:
                raise ValueError('native rollback result unaccepted')
            if self.path in self.checkpoints():
                self.call('CheckpointDestroy', 'o', self.path)
        if self.snapshot() != self.original:
            raise ValueError('original persistent settings not restored')
        self.phase = 'rolled_back'

    def confirm_timeout_rollback(self):
        if self.phase in ('new', 'committed', 'rolled_back') or not self.path:
            raise ValueError('pending checkpoint required')
        if self.path in self.checkpoints() or self.snapshot() != self.original:
            raise ValueError('native timeout restoration not established')
        self.phase = 'rolled_back'
