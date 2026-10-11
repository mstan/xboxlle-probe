"""Build a distinct guarded diagnostic XBE, without a live runner.

The stock SDK and default agent are unchanged. The generated private SDK core
uses a real exclusive IRQ, synchronous foreground service and stop/retention.
All its actual compiled memory accesses are routed through a closed owner;
unsupported MMIO writes fail before the store. Linkage is not capture success.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

import pefile

from noise_pair_build import SDK_SHA

ROOT=Path(__file__).resolve().parents[1]
SDK=Path('F:/Projects/xboxlle/refs/nxdk')
PRIMARY=Path('F:/Projects/xboxlle/refs/envytools-review-20261008')
PRIMARY_PIN='f102b82381f3f11cee113d16374c87091db039d9'
BIN=Path('C:/Users/Matthew/.local/share/retcomm/toolchains/cmake-clang-v1/latest/bin')
TYPES={'i1':'b1','i8':'i8','i16':'i16','i32':'i32','i64':'i64','float':'f32','double':'f64','ptr':'ptr'}

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(command,log):
    result=subprocess.run([str(x) for x in command],capture_output=True,text=True,timeout=90)
    log.write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError(f'{command[0]} failed: {result.stderr[-4000:]}')

def replace_function(text,name,new):
    match=re.search(r'(?m)^(?:static )?(?:BOOLEAN|int|void|NTAPI VOID)[^\n]*\b'+name+r'\s*\([^;]*?\)\s*\{',text)
    if not match:raise ValueError(f'missing unique function {name}')
    start=text.index('{',match.start());level=1;end=start+1
    # Pinned functions removed here contain no quoted brace literals.
    while level:
        if text[end]=='{':level+=1
        if text[end]=='}':level-=1
        end+=1
    return text[:start]+'{\n'+new+'\n}'+text[end:]

def once(text,old,new):
    if text.count(old)!=1:raise ValueError(f'unexpected pinned source shape: {old[:70]}')
    return text.replace(old,new)

def bounded_sdk(sdk=SDK):
    original=sdk/'lib/pbkit/pbkit.c'
    if digest(original)!=SDK_SHA:raise ValueError('SDK core differs from reviewed source')
    text=original.read_text()
    text=replace_function(text,'pb_install_gpu_interrupt','return noise_boot_irq_connect();')
    text=replace_function(text,'pb_uninstall_gpu_interrupt','noise_boot_abort(30);')
    text=replace_function(text,'ISR','return FALSE; /* no stock asynchronous handler */')
    text=replace_function(text,'pb_kill','noise_boot_abort(30); /* retain every resource */')
    text=replace_function(text,'pb_shutdown_notification_routine','noise_boot_abort(30);')
    text=once(text,'pb_set_gamma_ramp(&gammaRamp);',
              '/* Raw offscreen capture does not change the presentation DAC palette. */')
    text=once(text,'VIDEOREG(NV_PBUS_PCI_NV_1)|=NV_PBUS_PCI_NV_1_BUS_MASTER_ENABLED;',
              'noise_boot_bus_master(); /* DWORD command, zero PCI status W1C */')
    text=once(text,'VIDEOREG(NV_PBUS_PCI_NV_12)=NV_PBUS_PCI_NV_12_ROM_DECODE_DISABLED;\n'
                  '    VIDEOREG(NV_PBUS_PCI_NV_3)=NV_PBUS_PCI_NV_3_LATENCY_TIMER_248_CLOCKS;',
              'noise_boot_pci_setup(); /* preserved ROM address and header/BIST */')
    text=once(text,'VIDEOREG(NV_PMC_ENABLE)=NV_PMC_ENABLE_ALL_ENABLE;',
              'noise_boot_engine_setup(); /* documented engines, no blanket unknown-field transition */')
    text=once(text,'VIDEOREG(NV_PTIMER_NUMERATOR)=56968; //233333324/56968*7629=31247365 (31.25Mhz)\n'
                  '    VIDEOREG(NV_PTIMER_DENOMINATOR)=7629;\n\n'
                  '    VIDEOREG(NV_PTIMER_ALARM_0)=0xFFFFFFFF;',
              'noise_boot_timer_setup(); /* real ratio/compare producer, board-counter deadline */')
    text=once(text,'if (pb_install_gpu_interrupt()==0)\n    {',
              'if (pb_install_gpu_interrupt()==0)\n    {\n        noise_boot_abort(11);')
    text=once(text,'pb_running=1;','pb_running=1;\n    noise_boot_dpc_ready();')
    text=once(text,'__asm__ __volatile__ ("wbinvd");','noise_boot_wbinvd();')
    text=once(text,'HalRegisterShutdownNotification(&pb_shutdown_registration, TRUE);',
              '/* Diagnostic resources are retained; no stock shutdown/free callback. */')
    start=text.index('int pb_init(void)');end=text.index('static NTAPI VOID pb_shutdown_notification_routine',start)
    tail=text[start:end]
    if tail.count('return 0;')!=1:raise ValueError('initializer success shape changed')
    text=text[:start]+tail.replace('return 0;','pb_noise_initialized=1;\n    return 0;')+text[end:]
    # Include declarations first, then redirect only the pinned core's calls.
    prefix='''#include <hal/debug.h>
#include <assert.h>
#include <string.h>
#include "noise_gpu_bootstrap.h"
#define MmAllocateContiguousMemoryEx noise_boot_allocate
#define MmClaimGpuInstanceMemory noise_boot_instance
#define NtCreateEvent noise_boot_event
#define debugPrint noise_boot_debug_stop
#define memset noise_boot_sdk_memset
#define memcpy noise_boot_sdk_memcpy
#undef assert
#define assert(x) do { if(!(x)) noise_boot_abort(30); } while(0)
static int pb_noise_initialized;
'''
    return prefix+text+'\n'+(ROOT/'src/noise_pair_pbkit.inc').read_text()+'''
void noise_sdk_service(void) { DPC(NULL,NULL,NULL,NULL); }
'''

def instrument_ir(text):
    """Closed scalar opaque-pointer LLVM form; reject unhandled memory forms.

    This is a pinned build transformation, not a permissive regex fallback.
    Every core scalar load/store and memory intrinsic is counted; every block
    terminator polls the finite command owner. Unknown IR shapes fail the build.
    """
    counts={'loads':0,'stores':0,'blocks':0,'memcpy':0,'memset':0,'atomic_loads':0,'atomic_stores':0}
    result=[];in_function=False
    for line in text.splitlines():
        if line.startswith('define '):in_function=True
        if in_function:
            load=re.fullmatch(r'  (%[\w.]+) = load (?:volatile )?(i1|i8|i16|i32|i64|float|double|ptr), ptr (.+?), align \d+(?:, !.*)?',line)
            store=re.fullmatch(r'  store (?:volatile )?(i1|i8|i16|i32|i64|float|double|ptr) (.+?), ptr (.+?), align \d+(?:, !.*)?',line)
            memory=re.fullmatch(r'  (?:tail )?call void @llvm\.(memcpy|memset)\.p0\.(?:p0\.)?i32\(ptr (?:align \d+ )?([^,]+), (?:ptr (?:align \d+ )?|i8 )([^,]+), i32 ([^,]+), i1 false\)(?:.*)',line)
            atomic_load=re.fullmatch(r'  (%[\w.]+) = load atomic volatile (i8|i16|i32), ptr (.+?) acquire, align \d+(?:, !.*)?',line)
            atomic_store=re.fullmatch(r'  store atomic volatile (i8|i16|i32) (.+?), ptr (.+?) release, align \d+(?:, !.*)?',line)
            if atomic_load:
                symbol,kind,address=atomic_load.groups();line=f'  {symbol} = call {kind} @noise_boot_load_acquire_{kind}(ptr {address})';counts['atomic_loads']+=1
            elif atomic_store:
                kind,value,address=atomic_store.groups();line=f'  call void @noise_boot_store_release_{kind}(ptr {address}, {kind} {value})';counts['atomic_stores']+=1
            elif load:
                symbol,kind,address=load.groups();line=f'  {symbol} = call {kind} @noise_boot_load_{TYPES[kind]}(ptr {address})';counts['loads']+=1
            elif store:
                kind,value,address=store.groups();line=f'  call void @noise_boot_store_{TYPES[kind]}(ptr {address}, {kind} {value})';counts['stores']+=1
            elif memory:
                kind,destination,source,size=memory.groups()
                src_type='ptr' if kind=='memcpy' else 'i8'
                line=f'  call void @noise_boot_{kind}(ptr {destination}, {src_type} {source}, i32 {size})';counts[kind]+=1
            elif re.search(r'\b(?:load|store|atomicrmw|cmpxchg|memmove|llvm\.memcpy|llvm\.memset)\b',line):
                raise ValueError(f'unhandled memory IR: {line}')
            if re.match(r'  (?:br|switch|ret|unreachable)\b',line):
                result.append('  call void @noise_boot_poll()');counts['blocks']+=1
        if line.startswith('attributes '):
            # The injected owner has wider effects than the source's inferred
            # memory summaries. Do not preserve now-invalid optimizer promises.
            line=re.sub(r'\bmemory\([^)]*\)', '', line)
            line=re.sub(r'\b(?:nosync|nofree|willreturn|mustprogress|norecurse|readonly|readnone|speculatable|argmemonly)\b','',line)
        result.append(line)
        if line=='}':in_function=False
    if min(counts['loads']+counts['atomic_loads'],counts['stores']+counts['atomic_stores'],counts['blocks'])<100:
        raise ValueError('unexpectedly incomplete core instrumentation')
    existing=set(re.findall(r'@([\w.]+)\(',text))
    for kind,suffix in TYPES.items():
        for name,decl in [(f'noise_boot_load_{suffix}',f'{kind} (ptr)'),
                          (f'noise_boot_store_{suffix}',f'void (ptr, {kind})')]:
            if name not in existing:
                return_type,arguments=decl.split(' ',1);result.append(f'declare {return_type} @{name}{arguments}')
    for kind in ['i8','i16','i32']:
        result.append(f'declare {kind} @noise_boot_load_acquire_{kind}(ptr)')
        result.append(f'declare void @noise_boot_store_release_{kind}(ptr, {kind})')
    for name,arguments in [('noise_boot_poll','()'),('noise_boot_memcpy','(ptr, ptr, i32)'),
                           ('noise_boot_memset','(ptr, i8, i32)')]:
        if name not in existing:result.append(f'declare void @{name}{arguments}')
    return '\n'.join(result)+'\n',counts

def flags(sdk=SDK):
    includes=['lib','lib/xboxrt/libc_extensions','lib/pdclib/include',
              'lib/pdclib/platform/xbox/include','lib/winapi','lib/xboxrt/vcruntime',
              'lib/pbkit','lib/net/lwip/src/include','lib/net/nforceif/include','lib/net/nvnetdrv']
    result=['-target','i386-pc-win32','-march=pentium3','-ffreestanding','-nostdlib',
            '-fno-builtin','-DNXDK','-D__STDC__=1','-U__STDC_NO_THREADS__','-std=gnu11',
            '-Wno-builtin-macro-redefined','-I',str(ROOT/'src')]
    for include in includes:result+=['-I',str(sdk/include)]
    return result

def build(output,sdk=SDK,xbe=True):
    output.mkdir(parents=True,exist_ok=True)
    sources=['src/noise_gpu_bootstrap.c','src/noise_gpu_bootstrap.h',
             'host/noise_gpu_bootstrap_build.py','src/noise_pair_capture.c',
             'src/noise_pair_pbkit.inc','src/main.c','src/av_handshake.h',
             'tests/test_noise_gpu_bootstrap.py','docs/NOISE-GPU-BOOTSTRAP.md']
    for name in sources:
        path=output/'source'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((ROOT/name).read_bytes())
    private=output/'pbkit-bounded-private.c';private.write_text(bounded_sdk(sdk))
    clang=BIN/'clang.exe';linker=BIN/'ld.lld.exe';options=flags(sdk)
    ir=output/'pbkit-original.ll'
    run([clang,*options,'-O1','-fno-vectorize','-fno-slp-vectorize','-fno-unroll-loops',
         '-S','-emit-llvm',private,'-o',ir],output/'core-ir.log')
    checked,counts=instrument_ir(ir.read_text())
    instrumented=output/'pbkit-bounded.ll';instrumented.write_text(checked)
    objects=[]
    for source,name in [(instrumented,'pbkit-bounded.obj'),
                        (output/'source/src/noise_gpu_bootstrap.c','noise-bootstrap.obj'),
                        (output/'source/src/noise_pair_capture.c','noise-capture.obj'),
                        (output/'source/src/main.c','resident-agent.obj')]:
        obj=output/name
        run([clang,*options,'-O2','-c',source,'-o',obj],output/(name+'.log'));objects.append(obj)
    libraries=[sdk/'lib'/name for name in ['libpbkit.lib','libnxdk.lib','libnxdk_hal.lib',
               'libnxdk_net.lib','libpdclib.lib','libwinapi.lib','libxboxrt.lib']]
    libraries.append(sdk/'lib/xboxkrnl/libxboxkrnl.lib')
    exe=output/'noise-diagnostic.exe'
    exports=['noise_gpu_bootstrap','noise_gpu_capture','noise_gpu_bootstrap_result',
             'noise_pair_result']
    run([linker,'-flavor','link','-subsystem:windows','-fixed','-base:0x00010000',
         '-stack:65536','-merge:.edata=.edataxb','-entry:WinMainCRTStartup',
         '-out:'+str(exe),'-map:'+str(output/'noise-diagnostic.map'),
         *['-export:'+name for name in exports],*objects,*libraries],output/'link.log')
    if xbe:
        cxbe=output/'cxbe-noise.exe'
        cpp=[sdk/'tools/cxbe'/name for name in ['Main.cpp','Common.cpp','Error.cpp','Exe.cpp','Logo.cpp','Xbe.cpp']]
        run([Path('C:/msys64/mingw64/bin/g++.exe'),'-std=c++17','-O2','-static',*cpp,'-o',cxbe],output/'cxbe-build.log')
        run([cxbe,exe,'-OUT:'+str(output/'noise-diagnostic.xbe'),
             '-TITLE:xlle guarded noise diagnostic'],output/'cxbe.log')
    pe=pefile.PE(str(exe))
    mapped=pe.get_memory_mapped_image()
    entrypoints={entry.name.decode():dict(pe_address=pe.OPTIONAL_HEADER.ImageBase+entry.address,
                  rva=entry.address,initial_bytes=mapped[entry.address:entry.address+32].hex())
                 for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols if entry.name}
    converted_code=[]
    if xbe:
        data=(output/'noise-diagnostic.xbe').read_bytes()
        if data[:4]!=b'XBEH':raise ValueError('wrong converted image header')
        base=struct.unpack_from('<I',data,0x104)[0]
        relocated=struct.unpack_from('<I',data,0x13c)[0]
        count,section_table=struct.unpack_from('<II',data,0x11c)
        for index in range(count):
            section_flags,virtual,size,raw,length=struct.unpack_from('<5I',data,section_table-base+index*56)
            if section_flags&4:
                observed=data[raw:raw+length]
                expected=mapped[virtual-relocated:virtual-relocated+length]
                if relocated!=pe.OPTIONAL_HEADER.ImageBase or observed!=expected:
                    raise ValueError('converted executable section differs from target-linked proof')
                converted_code.append(dict(address=virtual,bytes=length,sha256=hashlib.sha256(observed).hexdigest()))
        for entry in entrypoints.values():
            address=relocated+entry['rva'];entry['xbe_address']=address
            for index in range(count):
                _,virtual,size,raw,length=struct.unpack_from('<5I',data,section_table-base+index*56)
                if virtual<=address<virtual+size:
                    # XBE uninitialized section tails are loader-owned BSS,
                    # not bytes at the next file section's raw offset.
                    section=data[raw:raw+length]+bytes(size-length)
                    observed=section[address-virtual:address-virtual+32]
                    # The fixed image must retain the same call/data bytes at
                    # every exported entry/result. No guessed PE->XBE address.
                    if relocated!=pe.OPTIONAL_HEADER.ImageBase or observed.hex()!=entry['initial_bytes']:
                        raise ValueError('converted entry identity differs from target-linked proof')
                    break
            else:raise ValueError('export missing from converted image')
    pe.close()
    paths=[p for p in output.rglob('*') if p.is_file()]
    paths += [sdk/'lib/pbkit/pbkit.c',clang,linker,*libraries]
    paths += list((sdk/'lib/pbkit').glob('*.h'))
    paths += list((sdk/'lib/xboxkrnl').glob('*.h'))
    paths += [sdk/'lib/hal'/name for name in ['video.h','xbox.h','debug.h']]
    primary_names=['rnndb/bus/pbus.xml','rnndb/bus/pci.xml','rnndb/bus/pmc.xml',
                   'rnndb/bus/ptimer.xml','rnndb/fifo/nv4_pfifo.xml',
                   'docs/hw/bus/bars.rst','docs/hw/bus/pmc.rst',
                   'docs/hw/bus/ptimer.rst','docs/hw/memory/nv4-vram.rst',
                   'hwtest/pgraph_state.cc','rnndb/display/nv_vga.xml',
                   'rnndb/display/nv3_prmvio.xml','rnndb/display/nv3_pcrtc.xml',
                   'rnndb/display/nv3_pramdac.xml']
    primary_names += ['docs/hw/pm/nv1-clock.rst']
    primary_inputs=[dict(path=str(PRIMARY/name),sha256=digest(PRIMARY/name),
                       url=f'https://github.com/envytools/envytools/blob/{PRIMARY_PIN}/{name}')
                    for name in primary_names]
    paths += [PRIMARY/name for name in primary_names]
    if xbe:
        paths += cpp+list((sdk/'tools/cxbe').glob('*.h'))+[Path('C:/msys64/mingw64/bin/g++.exe')]
    report=dict(scope='Linked guarded bootstrap/capture image; unsupported effects and live capture remain unqualified',
                network_operations=0,default_agent_unchanged=True,stock_sdk_unchanged=True,
                no_automatic_diagnostic_bootstrap=True,instrumented=counts,entrypoints=entrypoints,
                converted_executable_sections=converted_code,
                bootstrap_result_bytes=288,capture_result_bytes=1104,
                sdk_commit='29638d0b001f179b73c3513489af10ddc2986216',
                primary_commit=PRIMARY_PIN,primary_inputs=primary_inputs,
                artifacts=[dict(path=str(p),sha256=digest(p)) for p in paths])
    (output/'compiled-bootstrap.aot-private.json').write_text(json.dumps(report,indent=2))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--sdk',type=Path,default=SDK)
    parser.add_argument('--no-xbe',action='store_true')
    args=parser.parse_args();report=build(args.output,args.sdk,not args.no_xbe)
    print(json.dumps(dict(output=str(args.output),instrumented=report['instrumented'],network_operations=0)))
