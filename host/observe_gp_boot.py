#!/usr/bin/env python3
"""Closed owned-memory GP bootstrap marker under benign volatile-write authorization."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from payload_build import compile_fixed
from xbox_probe import AgentClient, ProbeError, _require_risk


def run(args):
    _require_risk(args, 'owned-memory GP bootstrap marker')
    output = args.output.resolve(); root = Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root / 'results'):
        raise ProbeError('raw console observations must remain private')
    output.mkdir(parents=True, exist_ok=False)
    code = compile_fixed('gp_boot')
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), status='started',
                  exec_request_may_have_been_sent=False, mmio_writes_permitted=7, automatic_retry=False,
                  payload_sha256=hashlib.sha256(code).hexdigest(), payload_bytes=len(code),
                  source_sha256=hashlib.sha256((root/'src/gp_boot_payload.c').read_bytes()).hexdigest(),
                  kernel_header_sha256=hashlib.sha256((root/'src/payload_kernel32.h').read_bytes()).hexdigest())
    def checkpoint():
        (output/'status.json').write_text(json.dumps(status, indent=2)+'\n')
    checkpoint(); agent = AgentClient(args.host, timeout=8.0)
    try:
        identity = agent.request('PING'); (output/'ping.txt').write_text(identity+'\n')
        if identity != 'PONG xboxlle-probe v0.4.0':
            raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status['exec_request_may_have_been_sent'] = True; checkpoint()
        reply = agent.request('EXEC '+str(len(code)), payload=code, dangerous=True)
        (output/'reply.txt').write_text(reply+'\n')
        if not re.fullmatch(r'RET [0-9a-fA-F]{8}', reply):
            raise ProbeError('malformed payload return; human inspection required')
        value = int(reply[4:], 16); polls = value & 0x1ffff
        if value>>24 != 0xd1 or value & 0x00fe0000 or not 1 <= polls <= 100000:
            raise ProbeError('GP precondition/boot/loaded image/stop/restoration failed; human inspection required')
        summary = dict(schema=1, status='owned_boot_marker_observed', marker=0x5a34c1,
                       poststart_marker_reads=polls, mmio_writes=7, reset_restored=0,
                       sg_address_max_restored=True, original_x_marker_restored=True,
                       observed_loaded_prefix_words=6, observed_loaded_final_word_index=2047,
                       retained_owned_scratch_bytes=28672, performance_counter_frequency=3375000,
                       maximum_poll_time_ms=50, automatic_retry=False,
                       limitations=['Authored marker in current quiet nxdk context, not original GP firmware',
                                    'Read count is not a measured boot latency',
                                    'No descriptor DMA/bit9, frame signalling, FIFO, EP or audio output qualification',
                                    'Sequential context checks do not atomically exclude other CPU writers',
                                    'Allocation retained until console restart'])
        (output/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
        status['status'] = 'observation_complete'; checkpoint()
        print('Owned GP boot marker observed; reset, SG configuration and X marker restored.'); return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error)); checkpoint()
        print('Stopped; evidence preserved privately. Human inspection required; no retry or restoring payload.', file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try: return run(parser.parse_args())
    except (OSError, ProbeError, ValueError, subprocess.SubprocessError) as error:
        print('Stopped before hardware commands: '+str(error), file=sys.stderr); return 2


if __name__ == '__main__': raise SystemExit(main())
