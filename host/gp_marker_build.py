"""Offline-only closed owned-GP marker bootstrap builder; no network runner."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

PHASES={'preflight':0,'start':1,'observe':2}
TOKEN=0x5a34c1


def compile_marker(phase,physical,original_sg,initial_marker=None):
    if phase not in PHASES:raise ValueError('outside closed marker phase list')
    for value,maximum in ((physical,0x4000000-36864),(original_sg,0x3ffc000)):
        if type(value) is not int or not 0<value<=maximum or value&16383:
            raise ValueError('expected exact16KiB physical/provenance address')
    if original_sg==physical:raise ValueError('original and calibrated addresses must differ')
    if phase=='preflight':
        if initial_marker is not None:raise ValueError('preflight discovers the marker')
    elif type(initial_marker) is not int or not 0<=initial_marker<=0xffffff or initial_marker==TOKEN:
        raise ValueError('expected exact preflight marker other than token')
    root=Path(__file__).resolve().parents[1]
    binary=Path('C:/msys64/mingw64/bin')
    def tool(name):
        path=binary/(name+'.exe')
        if not path.is_file():raise ValueError('offline compiler unavailable')
        return str(path)
    defines=['-DGP_MARKER_PHASE='+str(PHASES[phase]),
             '-DGP_MARKER_PHYSICAL='+hex(physical)+'u',
             '-DGP_MARKER_ORIGINAL_SG='+hex(original_sg)+'u']
    if phase!='preflight':defines.append('-DGP_MARKER_INITIAL='+hex(initial_marker)+'u')
    with tempfile.TemporaryDirectory(prefix='gp-marker-') as directory:
        obj=Path(directory)/'payload.o';raw=Path(directory)/'payload.bin'
        subprocess.run([tool('gcc'),'-m32','-Os','-std=c11','-Wall','-Wextra','-Werror',*defines,
            '-ffreestanding','-fno-stack-protector','-fno-pic','-fno-ident',
            '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',
            str(root/'src/gp_marker_payload.c'),'-o',str(obj)],check=True,capture_output=True,timeout=30)
        reloc=subprocess.check_output([tool('objdump'),'-r',str(obj)],text=True,timeout=10)
        if 'RELOCATION RECORDS FOR' in reloc:raise ValueError('unresolved relocation')
        symbols=subprocess.check_output([tool('objdump'),'-t',str(obj)],text=True,timeout=10)
        if not re.search(r'0{8}\s+_?gp_marker_probe\s*$',symbols,re.M):raise ValueError('nonzero entry')
        subprocess.run([tool('objcopy'),'-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True,timeout=10)
        data=raw.read_bytes()
        if not 1<=len(data)<=4096:raise ValueError('outside bounded EXEC size')
        return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=PHASES)
    parser.add_argument('--physical',type=lambda s:int(s,0),required=True)
    parser.add_argument('--original-sg',type=lambda s:int(s,0),required=True)
    parser.add_argument('--initial-marker',type=lambda s:int(s,0))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();data=compile_marker(args.phase,args.physical,args.original_sg,args.initial_marker)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('xb') as f:f.write(data)
    print(json.dumps(dict(phase=args.phase,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
        requested_reset=3 if args.phase=='start' else None,maximum_device_stores=int(args.phase=='start'),
        physical=args.physical,original_sg=args.original_sg,initial_marker=args.initial_marker,
        network_operations=0)))


if __name__=='__main__':main()
