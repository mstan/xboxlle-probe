"""Offline-only distinct low-RAM prepare/inspect/one-SG-store builder.

No network client, GP start, retry, high-address fallback, freeing or restoration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

PHASES={'prepare':0,'inspect':1,'calibrate':2}
BYTES=36864
ALIGNMENT=16384
MAX_BASE=0x600000
MAX_LAST=MAX_BASE+BYTES-1


def compile_lowram(phase,physical=None,original_sg=None):
    if phase not in PHASES:raise ValueError('outside closed low-RAM phase list')
    def address(value,maximum):
        if type(value) is not int or not 0<value<=maximum or value&(ALIGNMENT-1):
            raise ValueError('expected exact16KiB address within the closed bound')
    defines=['-DGP_LOWRAM_PHASE='+str(PHASES[phase])]
    if phase=='prepare':
        if physical is not None or original_sg is not None:
            raise ValueError('prepare accepts no host RAM address')
    else:
        address(physical,MAX_BASE);defines.append('-DGP_LOWRAM_PHYSICAL='+hex(physical)+'u')
        if phase=='inspect':
            if original_sg is not None:raise ValueError('inspect accepts no SG write context')
        else:
            address(original_sg,0x3ffc000)
            if original_sg==physical:raise ValueError('calibration requires a distinct actual old SG')
            defines.append('-DGP_LOWRAM_ORIGINAL_SG='+hex(original_sg)+'u')
    root=Path(__file__).resolve().parents[1]
    binary=Path('C:/msys64/mingw64/bin')
    def tool(name):
        path=binary/(name+'.exe')
        if not path.is_file():raise ValueError('offline compiler unavailable')
        return str(path)
    with tempfile.TemporaryDirectory(prefix='gp-lowram-') as directory:
        obj=Path(directory)/'payload.o';raw=Path(directory)/'payload.bin'
        subprocess.run([tool('gcc'),'-m32','-Os','-std=c11','-Wall','-Wextra','-Werror',*defines,
            '-ffreestanding','-fno-stack-protector','-fno-pic','-fno-ident',
            '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',
            str(root/'src/gp_lowram_payload.c'),'-o',str(obj)],check=True,capture_output=True,timeout=30)
        reloc=subprocess.check_output([tool('objdump'),'-r',str(obj)],text=True,timeout=10)
        if 'RELOCATION RECORDS FOR' in reloc:raise ValueError('unresolved relocation')
        symbols=subprocess.check_output([tool('objdump'),'-t',str(obj)],text=True,timeout=10)
        if not re.search(r'0{8}\s+_?gp_lowram_probe\s*$',symbols,re.M):raise ValueError('nonzero entry')
        subprocess.run([tool('objcopy'),'-O','binary','-j','.text',str(obj),str(raw)],
            check=True,capture_output=True,timeout=10)
        data=raw.read_bytes()
        if not 1<=len(data)<=4096:raise ValueError('outside bounded EXEC size')
        return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=PHASES)
    parser.add_argument('--physical',type=lambda s:int(s,0))
    parser.add_argument('--original-sg',type=lambda s:int(s,0))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();data=compile_lowram(args.phase,args.physical,args.original_sg)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('xb') as output:output.write(data)
    print(json.dumps(dict(phase=args.phase,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
        requested_allocation=dict(bytes=BYTES,lowest=0,highest_inclusive=MAX_LAST,
            alignment=ALIGNMENT,protect=0x204) if args.phase=='prepare' else None,
        maximum_base=MAX_BASE,physical=args.physical,original_sg=args.original_sg,
        requested_sg=args.physical if args.phase=='calibrate' else None,
        maximum_device_stores=int(args.phase=='calibrate'),network_operations=0)))


if __name__=='__main__':main()
