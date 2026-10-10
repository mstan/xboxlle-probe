#!/usr/bin/env python3
"""Fixed read-only follow-up: AV endpoints, PLL control, GPIO15 and FE control.

Owner authorization is still required; the risk flag does not provide it.
No upload, raw write, second AV transaction, GPIO output or FE command exists.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
import time

from read_av_context import returned_word
from xbox_probe import AgentClient, ProbeError, _require_risk


# MOV EAX,[absolute DWORD]; RET. GPIO: preserve flags/EDX, zero EAX,
# IN AL,DX at fixed 80CF, restore flags/EDX, RET. Stack saves are ordinary RAM.
OPERATIONS = (
    ('av_before', bytes.fromhex('a1 a00668fd c3'), 32),
    ('pll_control', bytes.fromhex('a1 0c0568fd c3'), 32),
    ('gpio15_control', bytes.fromhex('9c 52 66ba cf80 31c0 ec 5a 9d c3'), 8),
    ('fe_fence_control', bytes.fromhex('a1 101580fe c3'), 32),
    ('av_after', bytes.fromhex('a1 a00668fd c3'), 32),
)


def run(args):
    _require_risk(args, 'fixed read-only board-context EXEC batch')
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repo) and not output.is_relative_to(repo / 'results'):
        raise ProbeError('raw console observations must use ignored results/ or a private external directory')
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
        with (output / 'reads-raw.jsonl').open('x') as file:
            for name, payload, bits in OPERATIONS:
                status.update(stage=name,
                              exec_requests_may_have_been_sent=status['exec_requests_may_have_been_sent'] + 1)
                checkpoint()
                before = time.monotonic_ns()
                reply = agent.request('EXEC ' + str(len(payload)), payload=payload, dangerous=True)
                after = time.monotonic_ns()
                file.write(json.dumps(dict(name=name, payload_sha256=hashlib.sha256(payload).hexdigest(),
                                           reply=reply, host_interval_ns=[before, after])) + '\n')
                file.flush()
                value = returned_word(reply)
                if bits == 8 and (value > 255 or value == 255):
                    raise ProbeError('unexpected GPIO byte; stop without retry')
                if name.startswith('av_'):
                    if value not in (0, 0x11):
                        raise ProbeError('unexpected AV state; human inspection required')
                    if observations and value != observations[0]['value']:
                        raise ProbeError('changed AV endpoints; human inspection required')
                observations.append(dict(name=name, bits=bits, value=value))
        summary = dict(schema=1, status='context_observed', reads=len(observations),
                       hardware_writes_requested=0, observations=observations,
                       automatic_retry=False,
                       limitations=['Sequential context, not reset defaults or atomic state',
                                    'No GPIO output or flash operation',
                                    'FE control read does not qualify fences, DMA or completion ordering'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status.update(status='observation_complete', reads=len(observations)); checkpoint()
        print('Fixed board context observed: five reads, zero MMIO or I/O writes.')
        return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error),
                      complete_validated_reads=len(observations)); checkpoint()
        print('Stopped; private evidence preserved. Human inspection required; no retry.', file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try:
        return run(parser.parse_args())
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
