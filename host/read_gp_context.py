#!/usr/bin/env python3
"""Fixed read-only GP reset/scatter-gather context; never starts a DSP or DMA."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

from read_av_context import returned_word
from xbox_probe import AgentClient, ProbeError, _require_risk


# Factual offsets: pinned xemu apu_regs.h; GP aperture at APU + 0x30000.
# Pointer values are observed but never dereferenced or installed elsewhere.
OPERATIONS = (
    ('av_before', 0xfd6806a0),
    ('gp_reset_before', 0xfe83fffc),
    ('gp_scratch_sg_address', 0xfe802040),
    ('gp_scratch_sg_max', 0xfe8020d4),
    ('gp_fifo_sg_address', 0xfe802044),
    ('gp_fifo_sg_max', 0xfe8020d8),
    ('gp_reset_after', 0xfe83fffc),
    ('av_after', 0xfd6806a0),
)


def read_payload(address):
    if type(address) is not int or address not in {item[1] for item in OPERATIONS}:
        raise ProbeError('address outside the fixed GP-context list')
    return b'\xa1' + struct.pack('<I', address) + b'\xc3'


def run(args):
    _require_risk(args, 'fixed read-only GP context')
    output = args.output.resolve(); root = Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root / 'results'):
        raise ProbeError('raw console observations must remain private')
    output.mkdir(parents=True, exist_ok=False)
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', exec_requests_may_have_been_sent=0,
                  hardware_writes_requested=0, automatic_retry=False)
    observations = []; reset = None
    def checkpoint():
        (output / 'status.json').write_text(json.dumps(status, indent=2) + '\n')
    checkpoint(); agent = AgentClient(args.host, timeout=8.0)
    try:
        reply = agent.request('PING'); (output / 'ping.txt').write_text(reply + '\n')
        if reply != 'PONG xboxlle-probe v0.4.0':
            raise ProbeError('unexpected agent; stop before ARM/EXEC')
        with (output / 'reads-raw.jsonl').open('x') as file:
            for name, address in OPERATIONS:
                payload = read_payload(address)
                status.update(stage=name, exec_requests_may_have_been_sent=
                              status['exec_requests_may_have_been_sent'] + 1); checkpoint()
                reply = agent.request('EXEC 6', payload=payload, dangerous=True)
                file.write(json.dumps(dict(name=name, address=hex(address), reply=reply,
                                           payload_sha256=hashlib.sha256(payload).hexdigest())) + '\n'); file.flush()
                value = returned_word(reply)
                if name.startswith('av_') and value != 0x11:
                    raise ProbeError('changed AV context; stop for human inspection')
                if name == 'gp_reset_before': reset = value
                if name == 'gp_reset_after' and value != reset:
                    raise ProbeError('changed GP reset context; stop for human inspection')
                observations.append(dict(name=name, address=hex(address), value=value))
        summary = dict(schema=1, status='context_observed', reads=len(observations),
                       hardware_writes_requested=0, observations=observations,
                       automatic_retry=False,
                       limitations=['Sequential current nxdk context, not reset defaults',
                                    'No program/data memory or pointed-to RAM read',
                                    'No DSP reset/start, SG pointer, DMA, FIFO, IRQ or audio write',
                                    'Does not qualify DSP DMA bit9 or prove safe takeover'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status.update(status='observation_complete', reads=len(observations)); checkpoint()
        print('GP context observed: eight fixed DWORD reads, zero device writes.'); return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error)); checkpoint()
        print('Stopped; private evidence preserved. Human inspection required; no retry.', file=sys.stderr); return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try: return run(parser.parse_args())
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: ' + str(error), file=sys.stderr); return 2


if __name__ == '__main__': raise SystemExit(main())
