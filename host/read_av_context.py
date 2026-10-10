#!/usr/bin/env python3
"""Prepared, fixed read-only display context via reviewed ARM-guarded EXEC.

Requires separate explicit authorization under ../AGENTS.md. This module
does not infer authorization from the completed one-shot AV experiment.
Each six-byte payload is MOV EAX,[fixed DWORD address]; RET. No MMIO write,
I/O instruction, loop, new XBE, dashboard return or second AV request exists.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time

from xbox_probe import AgentClient, ProbeError, _require_risk


# Factual names/offsets: pinned envytools f102b82381f3f11cee113d16374c87091db039d9,
# rnndb/display/nv3_pramdac.xml. FD6806A0 has the owned-caller observation in
# docs/AV-HANDSHAKE.md, not independently known timing-bank semantics.
REGISTERS = (
    ('av_handshake', 0xfd6806a0),
    ('nvpll', 0xfd680500), ('mpll', 0xfd680504), ('vpll', 0xfd680508),
    ('general_control', 0xfd680600),
    ('fp_vdisplay_end', 0xfd680800), ('fp_vtotal', 0xfd680804), ('fp_vcrtc', 0xfd680808),
    ('fp_vsync_start', 0xfd68080c), ('fp_vsync_end', 0xfd680810),
    ('fp_vvalid_start', 0xfd680814), ('fp_vvalid_end', 0xfd680818),
    ('fp_hdisplay_end', 0xfd680820), ('fp_htotal', 0xfd680824), ('fp_hcrtc', 0xfd680828),
    ('fp_hsync_start', 0xfd68082c), ('fp_hsync_end', 0xfd680830),
    ('fp_hvalid_start', 0xfd680834), ('fp_hvalid_end', 0xfd680838),
    ('fp_dither', 0xfd68083c), ('fp_tg_control', 0xfd680848), ('fp_debug_0', 0xfd680880),
)


def read_payload(address):
    if type(address) is not int or address not in {item[1] for item in REGISTERS}:
        raise ProbeError('address is outside the fixed display-context list')
    return b'\xa1' + struct.pack('<I', address) + b'\xc3'


def returned_word(reply):
    if not re.fullmatch(r'RET [0-9a-fA-F]{1,8}', reply):
        raise ProbeError('malformed EXEC return; stop without retry')
    value = int(reply[4:], 16)
    if value == 0xffffffff:
        raise ProbeError('unexpected all-ones register value; human inspection required')
    return value


def run(args):
    _require_risk(args, 'fixed display-context EXEC batch')
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repo) and not output.is_relative_to(repo / 'results'):
        raise ProbeError('inside this repository, raw observations must be under ignored results/')
    output.mkdir(parents=True, exist_ok=False)
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', stage='identity', exec_requests_may_have_been_sent=0,
                  hardware_writes_requested=0, automatic_retry=False)
    observations = []
    def checkpoint():
        (output / 'status.json').write_text(json.dumps(status, indent=2) + '\n')
    checkpoint()
    agent = AgentClient(args.host, timeout=8.0)
    try:
        reply = agent.request('PING')
        (output / 'ping.txt').write_text(reply + '\n')
        if reply != 'PONG xboxlle-probe v0.4.0':
            raise ProbeError('unexpected agent; stop before ARM/EXEC')
        # The final repeated address is a stability observation, not a retry:
        # it only runs if every preceding distinct read completed successfully.
        operations = REGISTERS + (('av_handshake_final', REGISTERS[0][1]),)
        with (output / 'reads-raw.jsonl').open('x') as file:
            for name, address in operations:
                payload = read_payload(address)
                status['stage'] = name
                status['exec_requests_may_have_been_sent'] += 1
                checkpoint()
                before = time.monotonic_ns()
                reply = agent.request('EXEC 6', payload=payload, dangerous=True)
                after = time.monotonic_ns()
                row = dict(name=name, address=hex(address), payload_sha256=hashlib.sha256(payload).hexdigest(),
                           reply=reply, host_interval_ns=[before, after])
                file.write(json.dumps(row) + '\n'); file.flush()
                value = returned_word(reply)
                if address == 0xfd6806a0:
                    if value not in (0, 0x11):
                        raise ProbeError('AV word is not stable idle 0/0x11; human inspection required')
                    if observations and value != observations[0]['value']:
                        raise ProbeError('AV state changed across context reads; human inspection required')
                observations.append(dict(name=name, address=hex(address), value=value))
        summary = dict(schema=1, status='context_observed', reads=len(observations),
                       distinct_addresses=len(REGISTERS), hardware_writes_requested=0,
                       observations=observations, automatic_retry=False,
                       limitations=['Sequential non-atomic context in already-active nxdk mode',
                                    'No programmed/active-bank selection change',
                                    'No reset, reverse transition, commit or exact sync-edge qualification',
                                    'Host intervals include transport overhead, not GPU edge measurements'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status.update(status='observation_complete', reads=len(observations)); checkpoint()
        print('Fixed display context observed: 23 DWORD reads, zero MMIO writes.')
        return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error),
                      complete_validated_reads=len(observations)); checkpoint()
        print('Stopped; private results preserved. Human inspection or power cycle required; no retry.', file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
