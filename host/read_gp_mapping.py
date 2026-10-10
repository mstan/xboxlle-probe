#!/usr/bin/env python3
"""Fixed read-only kernel mapping query; never dereferences inherited SG RAM."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys

from payload_build import compile_fixed
from read_av_context import returned_word
from xbox_probe import AgentClient, ProbeError, _require_risk


def run(args):
    _require_risk(args, 'fixed read-only GP mapping query')
    root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root) and not output.is_relative_to(root/'results'):
        raise ProbeError('raw console observations must remain private')
    code=compile_fixed('gp_mapping')
    output.mkdir(parents=True,exist_ok=False)
    status=dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        status='started',exec_requests_may_have_been_sent=0,device_stores_requested=0,
        candidate_ram_loads_requested=0,automatic_retry=False,
        payload_sha256=hashlib.sha256(code).hexdigest())
    def save():
        (output/'status.json').write_text(json.dumps(status,indent=2)+'\n',newline='\n')
    save()
    try:
        agent=AgentClient(args.host,timeout=8.0)
        reply=agent.request('PING');(output/'ping.txt').write_text(reply+'\n',newline='\n')
        if reply!='PONG xboxlle-probe v0.4.0':raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status.update(status='executing',exec_requests_may_have_been_sent=1);save()
        reply=agent.request('EXEC '+str(len(code)),payload=code,dangerous=True)
        (output/'reply.txt').write_text(reply+'\n',newline='\n')
        value=returned_word(reply)
        if value&0xffffff00!=0xd2000000:
            raise ProbeError('mapping query stopped at its guarded stage: '+hex(value))
        mapped=value&15;matching=(value>>4)&15
        if matching&~mapped:raise ProbeError('contradictory physical mapping result')
        status.update(status='mapping_observed',mapped_pages_mask=mapped,
            matching_physical_pages_mask=matching,mapping_is_not_allocation_ownership=True,
            no_inherited_sg_read_authorized_by_result=True)
        save()
        print('Mapping query observed; zero device stores and zero inherited-RAM loads.')
        return 0
    except (OSError,ProbeError,ValueError) as error:
        status.update(status='stopped',error=str(error));save()
        print('Mapping query stopped; private evidence retained; no retry.',file=sys.stderr)
        return 2


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--i-accept-the-risk',action='store_true')
    try:return run(parser.parse_args())
    except (OSError,ProbeError,ValueError) as error:
        print('Stopped before hardware request: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
