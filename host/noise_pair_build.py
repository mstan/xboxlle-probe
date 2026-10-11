"""Compile post-bootstrap capture objects only; no network or live runner.

The default agent, SDK checkout and Makefile are not changed. A real separately
reviewed successful SDK bootstrap remains necessary; this does not wire capture
into the current resident app or claim a safe complete startup.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SDK_SHA='07323e1b5e7c3f3206868ed0b6b91ed3afe445bfc571d628fbd3bceedbba3e2a'

def build_objects(output,sdk=Path('F:/Projects/xboxlle/refs/nxdk')):
    root=Path(__file__).resolve().parents[1]
    original=sdk/'lib/pbkit/pbkit.c'
    if hashlib.sha256(original.read_bytes()).hexdigest()!=SDK_SHA:
        raise ValueError('SDK source differs from the reviewed pinned input')
    body=original.read_text()
    # Closed unique successful boot publication, not an external ready setter.
    start=body.index('int pb_init(void)')
    end=body.index('static NTAPI VOID pb_shutdown_notification_routine',start)
    tail=body[start:end]
    if tail.count('return 0;')!=1:raise ValueError('unexpected initializer success shape')
    patched=body[:start]+tail.replace('return 0;','pb_noise_initialized=1;\n    return 0;')+body[end:]
    patched='static int pb_noise_initialized;\n'+patched+'\n'+(root/'src/noise_pair_pbkit.inc').read_text()
    output.mkdir(parents=True,exist_ok=True)
    snapshots=output/'source';snapshots.mkdir(exist_ok=True)
    for name in ['src/noise_pair_capture.c','src/noise_pair_pbkit.inc','host/noise_pair_build.py']:
        destination=snapshots/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes((root/name).read_bytes())
    private=output/'pbkit-noise-private.c';private.write_text(patched)
    clang=Path('C:/Users/Matthew/.local/share/retcomm/toolchains/cmake-clang-v1/latest/bin/clang.exe')
    includes=['lib','lib/xboxrt/libc_extensions','lib/pdclib/include',
              'lib/pdclib/platform/xbox/include','lib/winapi','lib/xboxrt/vcruntime','lib/pbkit']
    flags=['-target','i386-pc-win32','-march=pentium3','-ffreestanding','-nostdlib',
           '-fno-builtin','-DNXDK','-D__STDC__=1','-U__STDC_NO_THREADS__','-std=gnu11',
           '-O2','-Wno-builtin-macro-redefined']
    for path in includes:flags+=['-I',str(sdk/path)]
    commands=[]
    for source,name in [(private,'pbkit-noise-private.obj'),
                        (snapshots/'src/noise_pair_capture.c','noise-pair-capture.obj')]:
        command=[str(clang),*flags,'-c',str(source),'-o',str(output/name)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
        (output/(name+'.log')).write_text(result.stdout+result.stderr)
        if result.returncode:raise RuntimeError(result.stderr)
        commands.append(command)
    paths=[original,root/'src/noise_pair_capture.c',root/'src/noise_pair_pbkit.inc',
           root/'host/noise_pair_build.py',private,clang,*output.glob('*.obj'),*output.glob('*.log'),
           *[p for p in snapshots.rglob('*') if p.is_file()]]
    report=dict(scope='Target objects compiled; bootstrap/integration/hardware not qualified',
                sdk_commit='29638d0b001f179b73c3513489af10ddc2986216',commands=commands,
                initialized_producer='only after genuine pb_init successful return',
                no_network=True,no_sdk_modification=True,no_default_agent_change=True,
                artifacts=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths])
    (output/'compiled-objects.aot-private.json').write_text(json.dumps(report,indent=2))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--sdk',type=Path,default=Path('F:/Projects/xboxlle/refs/nxdk'))
    args=parser.parse_args();r=build_objects(args.output,args.sdk)
    print(json.dumps(dict(output=str(args.output),artifacts=len(r['artifacts']),network_operations=0)))
