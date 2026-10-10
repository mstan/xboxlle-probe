#!/usr/bin/env python3
"""Ten fixed read-only display-mode context reads; no device stores."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

from read_av_context import returned_word
from xbox_probe import AgentClient, ProbeError, _require_risk


# Factual offsets: Linux v6.12 nouveau/dispnv04/nvreg.h. Read-only context,
# not an assumption about override semantics on NV2A.
OPERATIONS = (
    ('av_before', 0xfd6806a0, 0x11),
    ('fp_tg_control_before', 0xfd680848, 0x10100111),
    ('fp_debug_0', 0xfd680880, 0x21101100),
    ('fp_debug_1', 0xfd680884, None),
    ('fp_debug_2', 0xfd680888, None),
    ('fp_hvalid_start', 0xfd680834, 0),
    ('fp_hvalid_end', 0xfd680838, 639),
    ('fp_hdisplay_end', 0xfd680820, 639),
    ('fp_tg_control_after', 0xfd680848, 0x10100111),
    ('av_after', 0xfd6806a0, 0x11),
)


def read_payload(address):
    if type(address) is not int or address not in {item[1] for item in OPERATIONS}:
        raise ProbeError('address outside the fixed mode-context list')
    return b'\xa1' + struct.pack('<I', address) + b'\xc3'


def run(args):
    _require_risk(args, 'fixed read-only display-mode context')
    output = args.output.resolve()
    root = Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root / 'results'):
        raise ProbeError('raw console observations must remain private')
    output.mkdir(parents=True, exist_ok=False)
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', exec_requests_may_have_been_sent=0,
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
        with (output / 'reads-raw.jsonl').open('x') as file:
            for name, address, expected in OPERATIONS:
                payload = read_payload(address)
                status.update(stage=name, exec_requests_may_have_been_sent=
                              status['exec_requests_may_have_been_sent'] + 1)
                checkpoint()
                reply = agent.request('EXEC 6', payload=payload, dangerous=True)
                file.write(json.dumps(dict(name=name, address=hex(address), reply=reply,
                                           payload_sha256=hashlib.sha256(payload).hexdigest())) + '\n')
                file.flush()
                value = returned_word(reply)
                if expected is not None and value != expected:
                    raise ProbeError('context changed; stop for human inspection without retry')
                observations.append(dict(name=name, address=hex(address), value=value))
        summary = dict(schema=1, status='context_observed', reads=len(observations),
                       hardware_writes_requested=0, observations=observations,
                       automatic_retry=False,
                       limitations=['Sequential context in current nxdk mode, not reset defaults',
                                    'No bank selector, timing, scaling or AV write',
                                    'Register definitions do not prove override or activation semantics'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status.update(status='observation_complete', reads=len(observations)); checkpoint()
        print('Display-mode context observed: ten fixed DWORD reads, zero device writes.')
        return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error)); checkpoint()
        print('Stopped; evidence preserved privately. Human inspection required; no retry.', file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try:
        return run(parser.parse_args())
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: ' + str(error), file=sys.stderr); return 2


if __name__ == '__main__':
    raise SystemExit(main())
