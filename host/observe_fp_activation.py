#!/usr/bin/env python3
"""Fixed reversible one-pixel crop observation, under benign-write authorization."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from payload_build import compile_fixed
from xbox_probe import AgentClient,ProbeError,_require_risk


def run(args):
    _require_risk(args,'reversible one-pixel valid-window observation')
    output=args.output.resolve();root=Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root/'results'):
        raise ProbeError('raw observations must remain private')
    output.mkdir(parents=True,exist_ok=False)
    wait_window=getattr(args,'wait_window',False)
    code=compile_fixed('fp_activation',wait_window=wait_window)
    status=dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),status='started',
                exec_request_may_have_been_sent=False,mmio_writes_permitted=12,automatic_retry=False,
                payload_sha256=hashlib.sha256(code).hexdigest(),payload_bytes=len(code),
                source_sha256=hashlib.sha256((root/'src/fp_activation_payload.c').read_bytes()).hexdigest())
    status['wait_window']=wait_window
    status['kernel_header_sha256']=hashlib.sha256((root/'src/payload_kernel32.h').read_bytes()).hexdigest()
    def checkpoint():(output/'status.json').write_text(json.dumps(status,indent=2)+'\n')
    checkpoint();agent=AgentClient(args.host,timeout=8.0)
    try:
        identity=agent.request('PING');(output/'ping.txt').write_text(identity+'\n')
        if identity!='PONG xboxlle-probe v0.4.0':raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status['exec_request_may_have_been_sent']=True;checkpoint()
        reply=agent.request('EXEC '+str(len(code)),payload=code,dangerous=True)
        (output/'reply.txt').write_text(reply+'\n')
        if not re.fullmatch(r'RET [0-9a-fA-F]{8}',reply):raise ProbeError('malformed payload return')
        value=int(reply[4:],16);polls=(value>>5)&0x3ffff
        if value>>24!=0xc1 or value&0x00800000 or not value&16 or not 2<=polls<=200000:
            raise ProbeError('precondition, transaction, bank or restoration failed; human inspection required')
        summary=dict(schema=1,status='valid_window_observed',
                     active_start_before_request=value&1,active_start_after_ack=(value>>1)&1,
                     active_start_after_restore=0,pending_to_zero=bool(value&4),pending_to_one=bool(value&8),
                     total_postwrite_av_reads=polls,mmio_writes=12,original_control=0x10100111,
                     final_av=0x11,programmed_start_restored=0,automatic_retry=False,
                     minimum_post_ack_wait_ms=50 if wait_window else 0,
                     performance_counter_frequency=3375000 if wait_window else None,
                     limitations=['One horizontal valid-window field in current nxdk mode',
                                  'Sequential bank observations, no atomic exclusion of other kernel writers',
                                  'No clock/sync/total/enable write or electrical waveform observation',
                                  'No reset or exact activation-edge/delay measurement'])
        (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        status['status']='observation_complete';checkpoint()
        print('One-pixel valid-window observation complete; field, bank selector and AV phase restored.')
        return 0
    except(OSError,ProbeError,ValueError) as error:
        status.update(status='stopped_human_inspection_required',error=str(error));checkpoint()
        print('Stopped; private evidence preserved. Human inspection required; no retry or extra requests.',file=sys.stderr)
        return 2


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--i-accept-the-risk',action='store_true')
    parser.add_argument('--wait-window',action='store_true',help='distinct 50ms post-ack observation')
    try:return run(parser.parse_args())
    except(OSError,ProbeError,ValueError,subprocess.SubprocessError) as error:
        print('Stopped before hardware commands: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
