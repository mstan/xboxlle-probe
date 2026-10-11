"""Offline compiler for a closed list of reviewed freestanding x86 probes."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from xbox_probe import ProbeError

SOURCES = {'fe_fence': ('fe_fence_payload.c', 'fe_fence_probe'),
           'av_reverse': ('av_reverse_payload.c', 'av_reverse_probe'),
           'fp_activation': ('fp_activation_payload.c', 'fp_activation_probe'),
           'gp_boot': ('gp_boot_payload.c', 'gp_boot_probe'),
           'gp_mapping': ('gp_mapping_payload.c', 'gp_mapping_probe'),
           'fp_write_bank': ('fp_write_bank_payload.c', 'fp_write_bank_probe')}


def compile_fixed(name, held_window=False, wait_window=False):
    if (name not in SOURCES or type(held_window) is not bool or type(wait_window) is not bool
            or (name != 'fe_fence' and held_window) or (name != 'fp_activation' and wait_window)):
        raise ProbeError('payload is outside the closed reviewed variant list')
    root = Path(__file__).resolve().parents[1]
    binary = Path('C:/msys64/mingw64/bin') if os.name == 'nt' else None
    def tool(name):
        value = str(binary / (name + '.exe')) if binary else shutil.which(name)
        if not value or not Path(value).is_file(): raise ProbeError('required offline build tool unavailable: ' + name)
        return value
    source, symbol = SOURCES[name]
    with tempfile.TemporaryDirectory(prefix='fixed-x86-payload-') as directory:
        obj = Path(directory) / 'payload.o'; raw = Path(directory) / 'payload.bin'
        definitions = ['-DFE_OBSERVE_HELD='+str(int(held_window))] if name == 'fe_fence' else []
        if name=='fp_activation':definitions=['-DFP_WAIT_WINDOW='+str(int(wait_window))]
        subprocess.run([tool('gcc'), '-m32', '-Os', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        *definitions, '-ffreestanding', '-fno-stack-protector', '-fno-pic', '-fno-ident',
                        '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
                        '-c', str(root / 'src' / source), '-o', str(obj)],
                       check=True, capture_output=True, timeout=30)
        relocation = subprocess.check_output([tool('objdump'), '-r', str(obj)], text=True, timeout=10)
        if 'RELOCATION RECORDS FOR' in relocation: raise ProbeError('payload contains unresolved relocations')
        symbols = subprocess.check_output([tool('objdump'), '-t', str(obj)], text=True, timeout=10)
        if not re.search(r'0{8}\s+_?'+re.escape(symbol)+r'\s*$', symbols, re.M):
            raise ProbeError('payload entry is not text offset zero')
        subprocess.run([tool('objcopy'), '-O', 'binary', '-j', '.text', str(obj), str(raw)],
                       check=True, capture_output=True, timeout=10)
        code = raw.read_bytes()
        if not 1 <= len(code) <= 4096: raise ProbeError('unexpected payload size')
        return code
