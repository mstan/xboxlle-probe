#!/usr/bin/env python3
"""One owned-RAM FE fence observation; requires owner benign-write authorization.

Compiles and verifies the closed reviewed payload before connecting. No XBE
upload/launch and no arbitrary source/payload argument. See FE-FENCE.md.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from xbox_probe import AgentClient, ProbeError, _require_risk


def compiled_payload():
    root = Path(__file__).resolve().parents[1]
    binary = Path('C:/msys64/mingw64/bin') if os.name == 'nt' else None
    def tool(name):
        value = str(binary / (name + '.exe')) if binary else shutil.which(name)
        if not value or not Path(value).is_file(): raise ProbeError('required offline build tool unavailable: ' + name)
        return value
    with tempfile.TemporaryDirectory(prefix='fe-fence-payload-') as directory:
        obj = Path(directory) / 'payload.o'; raw = Path(directory) / 'payload.bin'
        subprocess.run([tool('gcc'), '-m32', '-Os', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-ffreestanding', '-fno-stack-protector', '-fno-pic', '-fno-ident',
                        '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
                        '-c', str(root / 'src/fe_fence_payload.c'), '-o', str(obj)],
                       check=True, capture_output=True, timeout=30)
        relocation = subprocess.check_output([tool('objdump'), '-r', str(obj)], text=True, timeout=10)
        if 'RELOCATION RECORDS FOR' in relocation: raise ProbeError('payload contains unresolved relocations')
        symbols = subprocess.check_output([tool('objdump'), '-t', str(obj)], text=True, timeout=10)
        if not re.search(r'0{8}\s+_?fe_fence_probe\s*$', symbols, re.M):
            raise ProbeError('payload entry is not text offset zero')
        subprocess.run([tool('objcopy'), '-O', 'binary', '-j', '.text', str(obj), str(raw)],
                       check=True, capture_output=True, timeout=10)
        code = raw.read_bytes()
        if not 1 <= len(code) <= 4096: raise ProbeError('unexpected payload size')
        return code


def run(args):
    _require_risk(args, 'owned-page bounded FE fence observation')
    output = args.output.resolve(); root = Path(__file__).resolve().parents[1]
    if output.is_relative_to(root) and not output.is_relative_to(root / 'results'):
        raise ProbeError('raw results must remain private')
    output.mkdir(parents=True, exist_ok=False)
    code = compiled_payload()
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', exec_request_may_have_been_sent=False,
                  payload_sha256=hashlib.sha256(code).hexdigest(), payload_bytes=len(code),
                  source_sha256=hashlib.sha256((root/'src/fe_fence_payload.c').read_bytes()).hexdigest(),
                  mmio_writes_permitted=5, retained_owned_scratch_bytes_max=4096,
                  automatic_retry=False)
    def checkpoint(): (output/'status.json').write_text(json.dumps(status, indent=2)+'\n')
    checkpoint(); agent = AgentClient(args.host, timeout=8.0)
    try:
        identity = agent.request('PING'); (output/'ping.txt').write_text(identity+'\n')
        if identity != 'PONG xboxlle-probe v0.4.0': raise ProbeError('unexpected agent; stop before ARM/EXEC')
        status['exec_request_may_have_been_sent']=True; checkpoint()
        reply = agent.request('EXEC '+str(len(code)), payload=code, dangerous=True)
        (output/'reply.txt').write_text(reply+'\n')
        if not re.fullmatch(r'RET [0-9a-fA-F]{8}', reply): raise ProbeError('malformed payload return')
        word = int(reply[4:],16); polls = word&0x1ffff
        if word>>24 != 0xf1 or word&0x00fe0000 or not 1 <= polls <= 100000:
            raise ProbeError('FE precondition/allocation/restore/fence observation failed; human inspection required')
        summary=dict(schema=1,status='owned_ram_fence_observed',polls=polls,mmio_writes=5,
                     restored_control=1,retained_owned_scratch_bytes=4096,automatic_retry=False,
                     limitations=['Idle application context; no queued audio-work or DMA ordering qualification',
                                  'Poll count is not a hardware delay measurement',
                                  'Page retained until restart to prevent late-write use after free'])
        (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        status['status']='observation_complete'; checkpoint()
        print('Owned RAM received the FE token; original control verified restored. Scratch page retained.')
        return 0
    except (OSError,ProbeError,ValueError) as error:
        status.update(status='stopped_human_inspection_required',error=str(error));checkpoint()
        print('Stopped; private evidence and any owned scratch retained. Human inspection required; no retry.',file=sys.stderr)
        return 2


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--i-accept-the-risk',action='store_true')
    try:return run(parser.parse_args())
    except (OSError,ProbeError,ValueError,subprocess.SubprocessError) as error:
        print('Stopped before hardware commands: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
