#!/usr/bin/env python3
"""Fixed read-only comparison of the PLL accesses reached by original Blinx.

Nine loads, no writes, retries, kernel calls or mode changes. Every EXEC keeps
the existing ARM gate. Clear any previous hardware stop by human inspection or
a power cycle before using this preparation under the owner's authorization.
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


# Pinned envytools f102b82381f3f11cee113d16374c87091db039d9,
# rnndb/display/nv3_pramdac.xml. These are exactly the DWORD/byte+1/DWORD
# sequences in the retained original title startup, not arbitrary BAR0 reads.
REGISTERS = (('nvpll', 0xfd680500), ('mpll', 0xfd680504), ('vpll', 0xfd680508))
OPERATIONS = tuple((name, address + (1 if width == 1 else 0), width, phase)
                   for name, address in REGISTERS
                   for width, phase in ((4, 'before'), (1, 'byte'), (4, 'after')))


def read_payload(address, width):
    if (type(address) is not int or type(width) is not int or
            (address, width) not in {(a, w) for _, a, w, _ in OPERATIONS}):
        raise ProbeError('read is outside the fixed PLL address/width list')
    encoded = struct.pack('<I', address)
    # MOV EAX,[address]; RET / MOVZX EAX,BYTE PTR [address]; RET.
    return (b'\xa1' if width == 4 else b'\x0f\xb6\x05') + encoded + b'\xc3'


def returned_word(reply, width):
    if not re.fullmatch(r'RET [0-9a-fA-F]{1,8}', reply):
        raise ProbeError('malformed EXEC return; human inspection required')
    value = int(reply[4:], 16)
    if value == 0xffffffff or (width == 1 and value > 0xff):
        raise ProbeError('unexpected PLL load result; human inspection required')
    return value


def run(args):
    _require_risk(args, 'fixed read-only PLL access-width comparison')
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repo) and not output.is_relative_to(repo / 'results'):
        raise ProbeError('inside this repository, raw observations must be under ignored results/')
    output.mkdir(parents=True, exist_ok=False)
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', stage='identity', exec_requests_may_have_been_sent=0,
                  hardware_writes_requested=0, automatic_retry=False)
    observations, comparison = [], {}

    def checkpoint():
        (output / 'status.json').write_text(json.dumps(status, indent=2) + '\n', encoding='utf-8')

    checkpoint()
    try:
        agent = AgentClient(args.host, timeout=8.0)
        reply = agent.request('PING')
        (output / 'ping.txt').write_text(reply + '\n', encoding='utf-8')
        if reply != 'PONG xboxlle-probe v0.4.0':
            raise ProbeError('unexpected agent; stop before ARM/EXEC')
        with (output / 'reads-raw.jsonl').open('x', encoding='utf-8') as file:
            for name, address, width, phase in OPERATIONS:
                payload = read_payload(address, width)
                status['stage'] = name + '_' + phase
                status['exec_requests_may_have_been_sent'] += 1
                checkpoint()
                before = time.monotonic_ns()
                reply = agent.request('EXEC ' + str(len(payload)), payload=payload, dangerous=True)
                after = time.monotonic_ns()
                row = dict(name=name, phase=phase, address=hex(address), width=width,
                           payload_sha256=hashlib.sha256(payload).hexdigest(), reply=reply,
                           host_interval_ns=[before, after])
                file.write(json.dumps(row) + '\n'); file.flush()
                value = returned_word(reply, width)
                if phase == 'before':
                    comparison[name] = value
                elif phase == 'byte' and value != ((comparison[name] >> 8) & 0xff):
                    raise ProbeError('PLL byte disagrees with preceding DWORD; human inspection required')
                elif phase == 'after' and value != comparison[name]:
                    raise ProbeError('PLL coefficient changed across width comparison; human inspection required')
                observations.append(dict(name=name, phase=phase, address=hex(address), width=width, value=value))
        summary = dict(schema=1, status='width_comparison_observed', reads=len(observations),
                       hardware_writes_requested=0, automatic_retry=False, observations=observations,
                       limitations=['Sequential non-atomic reads of the currently running mode',
                                    'Only the three original PLL byte+1 aliases are compared',
                                    'No halfword, other BAR0 width, reset, clock or write semantics established',
                                    'Host intervals include transport overhead; they do not measure GPU latency'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        status.update(status='observation_complete', reads=len(observations)); checkpoint()
        print('Original PLL width comparison observed: nine reads, zero hardware writes.')
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
