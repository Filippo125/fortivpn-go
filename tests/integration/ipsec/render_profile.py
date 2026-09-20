#!/usr/bin/env python3
"""Render the explicitly configured lab credentials into a private swanctl file."""
import argparse
import ipaddress
import json
import os
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--secrets', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--dual', action='store_true')
args = parser.parse_args()
source = Path(args.secrets)
if source.stat().st_mode & 0o077:
    raise SystemExit('secrets file must have permissions 0600')
cfg = json.loads(source.read_text())
ipaddress.ip_address(cfg['gateway'])
for field in ('gateway', 'username', 'password', 'psk'):
    value = cfg[field]
    if not isinstance(value, str) or not value or any(c in value for c in '\n\r\x00"\\'):
        raise SystemExit(f'unsupported characters or empty value in {field}')
vips = '0.0.0.0, ::' if args.dual else '0.0.0.0'
child6 = f'''
            lab6 {{
                local_ts = dynamic
                remote_ts = ::/0
                esp_proposals = aes256-sha256-modp2048
                start_action = none
            }}
''' if args.dual else ''
profile = f'''connections {{
    fortivpn-lab {{
        version = 2
        remote_addrs = {cfg['gateway']}
        proposals = aes256-sha256-modp2048
        vips = {vips}
        encap = yes
        mobike = no
        dpd_delay = 10s
        local {{
            auth = eap-mschapv2
            id = "{cfg['username']}"
            eap_id = "{cfg['username']}"
        }}
        remote {{
            auth = psk
            id = {cfg['gateway']}
        }}
        children {{
            lab4 {{
                local_ts = dynamic
                remote_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256-modp2048
                start_action = none
            }}
{child6}
        }}
    }}
}}
secrets {{
    ike-lab {{
        id = {cfg['gateway']}
        secret = "{cfg['psk']}"
    }}
    eap-lab {{
        id = "{cfg['username']}"
        secret = "{cfg['password']}"
    }}
}}
'''
fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write(profile)
print('Private lab profile created (credentials omitted).')
