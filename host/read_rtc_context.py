#!/usr/bin/env python3
"""Fixed RTC selector/alias observation; never writes CMOS contents.

Standing owner authorization covers these benign volatile index selections.
The ARM gate and explicit local acknowledgment remain required. Unexpected
post-selection values stop the batch without a retry or recovery write.
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

# Original kernel CMOS signature validator at 800187B4/800187C8 selects
# indexes using 72, then reads 71. These two data-port aliases are independently
# observed here. No OUT70, OUT71 or OUT73 instruction is present.
SELECTORS = ((0x10, 0x55), (0x80, 0x55), (0x81, 0xaa), (0xff, 0xaa))


def payload(selector):
    if type(selector) is not int or selector not in dict(SELECTORS):
        raise ProbeError('selector is outside the fixed RTC context list')
    # PUSHFD; CLI; PUSH EDX/ECX; OUT72,index; IN71; IN73; pack first:second;
    # restore ECX/EDX/FLAGS; RET. Interrupts are excluded only for this bounded
    # sequence so a concurrent RTC handler cannot change the shared selector.
    return (bytes.fromhex('9c fa 52 51 66ba 7200 b0') + bytes([selector]) +
            bytes.fromhex('ee 66ba 7100 31c0 ec 88c1 66ba 7300 ec '
                          '0fb6c9 c1e1 08 09c8 59 5a 9d c3'))


def run(args):
    _require_risk(args, 'fixed RTC selector and data-alias observation')
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repo) and not output.is_relative_to(repo / 'results'):
        raise ProbeError('console observations must use ignored results/ or a private directory')
    output.mkdir(parents=True, exist_ok=False)
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', stage='identity', exec_requests_may_have_been_sent=0,
                  selector_writes_may_have_been_sent=0, cmos_data_writes=0,
                  automatic_retry=False)
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
            for selector, expected in SELECTORS:
                code = payload(selector)
                status.update(stage=f'select_{selector:02x}',
                              exec_requests_may_have_been_sent=len(observations)+1,
                              selector_writes_may_have_been_sent=len(observations)+1)
                checkpoint()
                before = time.monotonic_ns()
                reply = agent.request('EXEC ' + str(len(code)), payload=code, dangerous=True)
                after = time.monotonic_ns()
                file.write(json.dumps(dict(selector=selector,
                    payload_sha256=hashlib.sha256(code).hexdigest(), reply=reply,
                    host_interval_ns=[before, after])) + '\n'); file.flush()
                value = returned_word(reply)
                if value != (expected << 8 | expected):
                    raise ProbeError('unexpected post-selection RTC alias/signature; no further write or retry')
                observations.append(dict(selector=selector, data71=value>>8, data73=value&255))
        summary = dict(schema=1, status='selector_alias_observed',
                       selector_writes=len(observations), data_reads=2*len(observations),
                       cmos_data_writes=0, observations=observations, automatic_retry=False,
                       limitations=['Current initialized CMOS, not reset/power-loss state',
                                    'No clock advancement, status, interrupt or NMI qualification',
                                    'Selector is left at FF; CMOS bytes are unchanged'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status.update(status='observation_complete', complete_validated_selections=len(observations))
        checkpoint(); print('RTC selector/alias observed: four index writes, eight reads, zero CMOS data writes.')
        return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error),
                      complete_validated_selections=len(observations)); checkpoint()
        print('Stopped; private evidence preserved; no retry or recovery write.', file=sys.stderr)
        return 2


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try:
        return run(parser.parse_args())
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: '+str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
