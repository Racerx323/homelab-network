#!/usr/bin/env python3
"""Authoritative local parser rendering inside a disposable network namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_policy import load_policy, nft_rules, normalized_table, digest

if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
    raise SystemExit('refusing initial network namespace')
rules = nft_rules(load_policy())
subprocess.run(['/usr/sbin/nft','--check','-f','-'],input=rules,text=True,check=True)
subprocess.run(['/usr/sbin/nft','-f','-'],input=rules,text=True,check=True)
r = subprocess.run(['/usr/sbin/nft','-j','list','table','inet','nautobot_backend'],text=True,capture_output=True,check=True)
print(digest(normalized_table(json.loads(r.stdout))))
