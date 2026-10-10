#!/usr/bin/env python3
"""One bounded, reversible READ_PROG selector observation; no mode/AV change.

The owner must authorize benign volatile register writes. See FP-BANKS.md.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys

from xbox_probe import AgentClient, ProbeError, _require_risk


def payload():
    # Closed instruction sequence, no external address or code input. Save
    # caller flags/ECX/EDX. Only READ_PROG changes; preserve fresh other bits.
    code = bytearray(); jumps = []; labels = {}
    def emit(value): code.extend(bytes.fromhex(value))
    def jump(opcode, target):
        emit(opcode); jumps.append((len(code), target)); code.append(0)
    emit('9c 52 51')                          # PUSHFD; PUSH EDX; PUSH ECX
    emit('a1 480868fd 3d 11011010')           # initial control must be 10100111
    jump('75', 'error')
    emit('25 ffffefff a3 480868fd')           # clear bit20, one selector write
    emit('a1 480868fd 3d 11010010')           # verify selected bank before reads
    jump('75', 'invalid_bank')
    emit('8b0d 240868fd 8b15 040868fd')       # H/V TOTAL, one DWORD each
    jump('eb', 'restore')
    labels['invalid_bank'] = len(code); emit('b9 ffffffff ba ffffffff')
    labels['restore'] = len(code)
    emit('a1 480868fd 3d 11010010')           # reject changed fresh control before store
    jump('75', 'error')
    emit('0d 00001000 a3 480868fd')           # restore only known bit20
    emit('a1 480868fd 3d 11011010')           # verify actual restored control
    jump('75', 'error')
    emit('81f9 ff0f0000'); jump('77', 'error') # reject unexpected timing widths
    emit('81fa ff0f0000'); jump('77', 'error')
    emit('c1e2 0c 89c8 09d0 0d 000000ab')    # AB tag + 12-bit V/H totals
    jump('eb', 'done')
    labels['error'] = len(code); emit('b8 ffffffff')
    labels['done'] = len(code); emit('59 5a 9d c3')
    for offset, target in jumps:
        relative = labels[target] - offset - 1
        if not -128 <= relative <= 127: raise ValueError('closed payload branch exceeds rel8')
        code[offset] = relative & 255
    return bytes(code)


def run(args):
    _require_risk(args, 'reversible fixed FP bank selector observation')
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repo) and not output.is_relative_to(repo / 'results'):
        raise ProbeError('raw console observations must remain private')
    output.mkdir(parents=True, exist_ok=False)
    code = payload()
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', exec_request_may_have_been_sent=False,
                  mmio_writes_permitted=2, automatic_retry=False,
                  payload_sha256=hashlib.sha256(code).hexdigest(), payload_bytes=len(code))
    def checkpoint():
        (output / 'status.json').write_text(json.dumps(status, indent=2) + '\n')
    checkpoint()
    agent = AgentClient(args.host, timeout=8.0)
    try:
        identity = agent.request('PING')
        (output / 'ping.txt').write_text(identity + '\n')
        if identity != 'PONG xboxlle-probe v0.4.0':
            raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status['exec_request_may_have_been_sent'] = True; checkpoint()
        reply = agent.request('EXEC ' + str(len(code)), payload=code, dangerous=True)
        (output / 'reply.txt').write_text(reply + '\n')
        if len(reply) != 12 or not reply.startswith('RET '):
            raise ProbeError('malformed return; human inspection required')
        value = int(reply[4:], 16)
        if value >> 24 != 0xab:
            raise ProbeError('precondition, timing width or restored-selector check failed; stop')
        summary = dict(schema=1, status='active_totals_observed', htotal=value & 4095,
                       vtotal=(value >> 12) & 4095, restored_control=0x10100111,
                       mmio_writes=2, written_address='FD680848', changed_bit=20,
                       automatic_retry=False,
                       limitations=['Bank selection interpretation uses pinned register definitions',
                                    'No new mode, AV request, reset or sync-edge observation',
                                    'No electrical sync or counter-phase measurement'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status['status'] = 'observation_complete'; checkpoint()
        print('FP bank totals observed; original read selector verified restored.')
        return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error)); checkpoint()
        print('Stopped; private evidence preserved. Human inspection required; no retry.', file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try: return run(parser.parse_args())
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: ' + str(error), file=sys.stderr); return 2


if __name__ == '__main__': raise SystemExit(main())
