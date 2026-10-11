#!/usr/bin/env python3
"""Fixed reversible one-pixel bank-write observation under standing permission."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from payload_build import compile_fixed
from xbox_probe import AgentClient, ProbeError, _require_risk

def run(args):
    _require_risk(args, 'fixed one-pixel write-bank observation')
    output=args.output.resolve();root=Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root/'results'):
        raise ProbeError('raw observations must remain private')
    code=compile_fixed('fp_write_bank')
    output.mkdir(parents=True,exist_ok=False)
    status=dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        status='started',exec_request_may_have_been_sent=False,maximum_mmio_writes=7,
        payload_sha256=hashlib.sha256(code).hexdigest(),payload_bytes=len(code),
        source_sha256=hashlib.sha256((root/'src/fp_write_bank_payload.c').read_bytes()).hexdigest(),
        automatic_retry=False)
    def checkpoint():
        (output/'status.json').write_bytes((json.dumps(status,indent=2)+'\n').encode('utf-8'))
    checkpoint();agent=AgentClient(args.host,timeout=8.0)
    try:
        identity=agent.request('PING');(output/'ping.txt').write_bytes((identity+'\n').encode('utf-8'))
        if identity!='PONG xboxlle-probe v0.4.0':raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status['exec_request_may_have_been_sent']=True;checkpoint()
        reply=agent.request('EXEC '+str(len(code)),payload=code,dangerous=True)
        (output/'reply.txt').write_bytes((reply+'\n').encode('utf-8'))
        if not re.fullmatch(r'RET [0-9a-fA-F]{8}',reply):raise ProbeError('malformed payload return')
        value=int(reply[4:],16)
        if value&0xfffffff0!=0xc2000080:
            raise ProbeError('unexpected precondition/readback/restoration; no further hardware operation')
        summary=dict(status='write_bank_observed',selected_after_write=value&1,
            programmed_after_write=(value>>1)&1,selected_after_program_restore=(value>>2)&1,
            unchanged_av_phase=0x11 if value&8 else 0,mmio_writes=7,
            both_windows_restored=0,original_selector_restored=0x10100111,
            automatic_retry=False,
            limitations=['One field in current nxdk mode; alternate read view is not claimed as active output',
                        'No AV request, timing activation, reset, electrical or counter-phase measurement',
                        'No atomic exclusion of ordinary kernel/device activity'])
        (output/'summary.json').write_bytes((json.dumps(summary,indent=2)+'\n').encode('utf-8'))
        status['status']='observation_complete';checkpoint()
        print('Fixed write-bank observation complete; both windows, selector and AV phase preserved.')
        return 0
    except (OSError,ProbeError,ValueError) as error:
        status.update(status='stopped_no_retry',error=str(error));checkpoint()
        print('Stopped; private evidence preserved. No further hardware operation.',file=sys.stderr)
        return 2

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--i-accept-the-risk',action='store_true')
    try:return run(parser.parse_args())
    except (OSError,ProbeError,ValueError) as error:
        print('Stopped before hardware command: '+str(error),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
