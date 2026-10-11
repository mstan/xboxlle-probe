"""Offline-only builder for the three closed owned-RAM calibration phases.

This module has no network client or hardware runner. A calibrated SG write is
a new separately reviewed experiment, never an automatic retry of gp_boot.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

PHASES = {'prepare': 0, 'inspect': 1, 'calibrate': 2}
BYTES = 36864
TABLE_ALIGNMENT = 16384


def authored_b3_image():
    """Finite diagnostic stimulus; configuration meaning remains unresolved.

    No original firmware is included. Three factual immediate MOVEP inputs
    match the reached configuration tuple. Two unequal finite NOP intervals
    precede B3 samples; owned X100/101/102 and X104 are the only RAM targets.
    This function does not construct or authorize a bootstrap/start payload.
    """
    words = [0x07f432, 0xffffff, 0x07f430, 1, 0x07f431, 1,
             0x44f000, 0xffffb3, 0x447000, 0x100]
    words += [0]*16
    words += [0x44f000, 0xffffb3, 0x447000, 0x101]
    words += [0]*64
    words += [0x44f000, 0xffffb3, 0x447000, 0x102,
              0x44f400, 0x5a34c1, 0x447000, 0x104, 0x87]
    assert len(words)==103
    return struct.pack('<4096I',*(words+[0x87]*(4096-len(words))))


def compile_owned(phase, physical=None, original_sg=None):
    if phase not in PHASES:
        raise ValueError('outside the closed phase list')
    def address(value, maximum):
        if type(value) is not int or not 0 < value <= maximum or value & (TABLE_ALIGNMENT-1):
            raise ValueError('expected an exact16KiB-aligned physical address')
    definitions = ['-DGP_OWNED_MODE=' + str(PHASES[phase])]
    if phase == 'prepare':
        if physical is not None or original_sg is not None:
            raise ValueError('prepare accepts no inherited/host RAM address')
    else:
        address(physical, 0x4000000-BYTES)
        definitions.append('-DGP_OWNED_PHYSICAL=' + hex(physical)+'u')
        if phase == 'inspect':
            if original_sg is not None:
                raise ValueError('inspect accepts no SG write target')
        else:
            address(original_sg, 0x3fff000)
            if original_sg == physical:
                raise ValueError('calibration must change the established old SG address')
            definitions.append('-DGP_OWNED_ORIGINAL_SG='+hex(original_sg)+'u')
    root = Path(__file__).resolve().parents[1]
    binary = Path('C:/msys64/mingw64/bin')
    def tool(name):
        result=binary/(name+'.exe')
        if not result.is_file(): raise ValueError('offline compiler unavailable: '+name)
        return str(result)
    with tempfile.TemporaryDirectory(prefix='gp-owned-') as directory:
        obj=Path(directory)/'payload.o'; raw=Path(directory)/'payload.bin'
        subprocess.run([tool('gcc'), '-m32', '-Os', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        *definitions, '-ffreestanding', '-fno-stack-protector', '-fno-pic', '-fno-ident',
                        '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-c',
                        str(root/'src/gp_owned_payload.c'), '-o', str(obj)],
                       check=True, capture_output=True, timeout=30)
        reloc=subprocess.check_output([tool('objdump'),'-r',str(obj)],text=True,timeout=10)
        if 'RELOCATION RECORDS FOR' in reloc: raise ValueError('unresolved payload relocation')
        symbols=subprocess.check_output([tool('objdump'),'-t',str(obj)],text=True,timeout=10)
        if not re.search(r'0{8}\s+_?gp_owned_probe\s*$',symbols,re.M):
            raise ValueError('entry is not offset zero')
        subprocess.run([tool('objcopy'),'-O','binary','-j','.text',str(obj),str(raw)],
                       check=True,capture_output=True,timeout=10)
        code=raw.read_bytes()
        if not 1 <= len(code) <= 4096: raise ValueError('outside bounded EXEC size')
        return code


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=PHASES)
    parser.add_argument('--physical',type=lambda s:int(s,0))
    parser.add_argument('--original-sg',type=lambda s:int(s,0))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    code=compile_owned(args.phase,args.physical,args.original_sg)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('xb') as stream: stream.write(code)
    print(json.dumps(dict(phase=args.phase,bytes=len(code),sha256=hashlib.sha256(code).hexdigest(),
                          physical=args.physical,original_sg=args.original_sg,
                          network_operations=0,maximum_device_stores=int(args.phase=='calibrate'))))


if __name__=='__main__': main()
