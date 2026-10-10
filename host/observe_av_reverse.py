#!/usr/bin/env python3
"""Fixed AV0->request1 observation under owner benign-write authorization."""
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
    _require_risk(args,'fixed reverse-direction AV request')
    output=args.output.resolve();root=Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root/'results'):
        raise ProbeError('raw observations must remain private')
    output.mkdir(parents=True,exist_ok=False)
    code=compile_fixed('av_reverse')
    status=dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),status='started',
                exec_request_may_have_been_sent=False,mmio_writes_permitted=1,automatic_retry=False,
                payload_sha256=hashlib.sha256(code).hexdigest(),payload_bytes=len(code),
                source_sha256=hashlib.sha256((root/'src/av_reverse_payload.c').read_bytes()).hexdigest())
    def checkpoint():(output/'status.json').write_text(json.dumps(status,indent=2)+'\n')
    checkpoint();agent=AgentClient(args.host,timeout=8.0)
    try:
        identity=agent.request('PING');(output/'ping.txt').write_text(identity+'\n')
        if identity!='PONG xboxlle-probe v0.4.0':raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status['exec_request_may_have_been_sent']=True;checkpoint()
        reply=agent.request('EXEC '+str(len(code)),payload=code,dangerous=True)
        (output/'reply.txt').write_text(reply+'\n')
        if not re.fullmatch(r'RET [0-9a-fA-F]{8}',reply):raise ProbeError('malformed payload return')
        value=int(reply[4:],16);polls=value&0x1ffff;first=(value>>17)&3
        if value>>24!=0xe1 or value&0x00f80000 or first not in (1,3) or not 1<=polls<=100000:
            raise ProbeError('AV precondition, request/ack or polling bound failed; human inspection required')
        summary=dict(schema=1,status='reverse_ack_observed',initial=0,request=1,ack=0x11,
                     first_postwrite=1 if first==1 else 0x11,postwrite_reads=polls,
                     mmio_writes=1,automatic_retry=False,restoring_request=False,
                     limitations=['No mode register changed; phase remains1 after success',
                                  'No reset or timing-bank activation qualification',
                                  'Poll count is not a measured hardware delay'])
        (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        status['status']='observation_complete';checkpoint()
        print('Reverse AV acknowledgment observed; one request write, no retry.')
        return 0
    except (OSError,ProbeError,ValueError) as error:
        status.update(status='stopped_human_inspection_required',error=str(error));checkpoint()
        print('Stopped; private evidence preserved. Human inspection required; no retry.',file=sys.stderr)
        return 2


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--i-accept-the-risk',action='store_true')
    try:return run(parser.parse_args())
    except (OSError,ProbeError,ValueError,subprocess.SubprocessError) as error:
        print('Stopped before hardware commands: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
