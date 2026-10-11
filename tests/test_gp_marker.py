"""Actual closed x86 variants against independent owned/bootstrap models."""
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
from gp_marker_build import compile_marker,TOKEN
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_ESI,
                              UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)

OLD=0x399c000
INITIAL=0x123456


@lru_cache(maxsize=None)
def code(phase,physical,initial=INITIAL):return compile_marker(phase,physical,OLD,None if phase=='preflight' else initial)


def owned_model(physical):
    words=[0x87]*9216
    for i in range(2048):words[2*i:2*i+2]=[physical+((i+4)*4096 if i<4 else 7*4096),0]
    words[4096:4102]=[0x65f400,0xfc,0x44f400,TOKEN,0x021584,0x87]
    words[8192:8196]=[0x47504f31,physical,OLD,0x47504f31^physical^OLD]
    return struct.pack('<9216I',*words)


class MarkerTests(unittest.TestCase):
    def execute(self,phase='start',physical=0x180000,context=None,fail=None,
                marker_after=1,readback=None,wrong_p=None,clock_values=None,
                clock_step=1000,clear_x=False,mutate=None,frequency=3375000,initial=INITIAL):
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        payload=code(phase,physical,initial)
        uc.mem_map(0x1000,4096);uc.mem_write(0x1000,payload)
        uc.mem_map(0x5000,4096);uc.mem_map(0x6000,0x3000)
        uc.mem_write(0x8000,struct.pack('<I',0x5000));uc.reg_write(UC_X86_REG_ESP,0x8000)
        uc.mem_map(0x80010000,0x40000);uc.mem_map(0xfd680000,4096)
        uc.mem_map(0xfe801000,0x2000);uc.mem_map(0xfe830000,0x10000)
        base=0x80000000|physical;uc.mem_map(base,36864);uc.mem_write(base,owned_model(physical))
        def put(a,v):uc.mem_write(a,struct.pack('<I',v))
        for offset,value in (mutate or {}).items():put(base+offset,value)
        before=bytes(uc.mem_read(base,36864))
        uc.mem_write(0x80010000,b'MZ');put(0x8001003c,0x80);put(0x80010080,0x4550)
        uc.mem_write(0x80010098,struct.pack('<H',0x10b));put(0x800100d0,0x40000)
        put(0x800100f8,0x2000);put(0x800100fc,0x1000)
        put(0x80012010,1);put(0x80012014,400);put(0x8001201c,0x2400)
        exports={173:0xa000,174:0xb000,179:0xc000,180:0xd000,126:0xe000,127:0xf000}
        for ordinal,rva in exports.items():put(0x80012400+(ordinal-1)*4,rva)
        if fail=='missing-clock':put(0x80012400+(126-1)*4,0)
        regs={0xfe83fffc:3 if phase=='observe' else 0,0xfe801004:0xafa,
              0xfe802000:7,0xfe801100:0x71f8f,0xfe801000:0,0xfd6806a0:0x11,
              0xfe802040:physical,0xfe8020d4:1544,0xfe830400:initial}
        regs.update(context or {})
        # Independent loader consumes actual modeled SG entries, not a claimed
        # image or manufactured prefix expected by the x86 observer.
        def bootstrap():
            pages=[]
            for index in range(2):
                page,pad=struct.unpack('<II',uc.mem_read(base+index*8,8))
                self.assertEqual(pad,0);self.assertTrue(physical<=page<physical+36864)
                pages.append(bytes(uc.mem_read(base+page-physical,4096)))
            return b''.join(pages)
        image=[bootstrap() if phase=='observe' else None]
        events=[];ram_reads=[];stores=[];polls=[0];ticks=[1<<40];clocks=[0];wrote=[False]
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items():uc.reg_write(reg,value)
        def kernel(u,a,size,unused):
            ordinal=next((o for o,r in exports.items() if a==0x80010000+r),None)
            if ordinal is None:return
            self.assertFalse(wrote[0],'kernel/time operation after reset store')
            sp=u.reg_read(UC_X86_REG_ESP);count=0 if ordinal in (126,127) else 1
            args=struct.unpack('<I',u.mem_read(sp+4,4)) if count else ()
            events.append(('kernel',ordinal,args))
            if ordinal==174:
                a=args[0];value=int(a==0x80010000 or base<=a<base+36864)
                if fail=='boolean-calibration' and a==0x40000000:value=1
                if fail=='mapping' and a==base+4096:value=0
                value|=0xabcde000
            elif ordinal==173:
                self.assertTrue(args[0]==0x80010000 or base<=args[0]<base+36864)
                value=0x10000 if args[0]==0x80010000 else physical+args[0]-base
                if fail=='physical' and args[0]==base+8191:value+=4096
            elif ordinal==179:value=4 if fail=='protect' and args[0]==base+4096 else 0x204
            elif ordinal==180:value=32768 if fail=='extent' else 36864
            elif ordinal==127:value=frequency
            else:
                index=clocks[0];clocks[0]+=1
                if clock_values is not None:value=clock_values[min(index,len(clock_values)-1)]
                else:ticks[0]+=clock_step;value=ticks[0]
            u.reg_write(UC_X86_REG_EAX,value&0xffffffff);u.reg_write(UC_X86_REG_EDX,value>>32)
            u.reg_write(UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(UC_X86_REG_ESP,sp+4+count*4)
        def read(u,access,a,size,value,unused):
            if a>=0xfd000000:
                self.assertEqual(size,4);events.append(('read',a))
                if 0xfe83a000<=a<=0xfe83bffc:
                    self.assertEqual(phase,'observe');self.assertIsNotNone(image[0])
                    index=(a-0xfe83a000)//4;value=struct.unpack_from('<I',image[0],index*4)[0]
                    if wrong_p==index:value^=1
                else:
                    self.assertIn(a,regs)
                    if fail=='context-drift' and a==0xfe83fffc and sum(e==('read',a) for e in events)>1:regs[a]=7
                    value=regs[a]
                    if a==0xfe830400 and phase=='observe':
                        polls[0]+=1
                        if marker_after is not None and polls[0]>=marker_after:value=TOKEN
                        elif clear_x:value=0
                        if fail=='unexpected-marker':value=0xdeadbe
                put(a,value)
            elif base<=a<base+36864:
                self.assertFalse(wrote[0]);self.assertEqual(size,4);ram_reads.append(a-base)
        def write(u,access,a,size,value,unused):
            if a>=0xfd000000:
                self.assertEqual(phase,'start');self.assertEqual((a,size,value),(0xfe83fffc,4,3))
                self.assertFalse(wrote[0]);wrote[0]=True;stores.append((a,value));events.append(('write',a,value))
                regs[a]=value if readback is None else readback
                image[0]=bootstrap()
            else:self.assertTrue(0x6000<=a and a+size<=0x8000,'non-stack CPU store')
        uc.hook_add(UC_HOOK_CODE,kernel);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x5000,count=20000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x5000);self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        self.assertEqual(bytes(uc.mem_read(base,36864)),before)
        result=dict(result=uc.reg_read(UC_X86_REG_EAX),events=events,ram_reads=ram_reads,stores=stores,
                    marker_reads=polls[0],clock_calls=clocks[0],image=image[0],ram=before)
        artifact_dir=os.environ.get('PROBE_GP_MARKER_ARTIFACT_DIR')
        if artifact_dir:
            directory=Path(artifact_dir)/f'{len(list(Path(artifact_dir).glob("context-*"))):03d}'
            directory=directory.with_name('context-'+directory.name);directory.mkdir()
            (directory/'payload.bin').write_bytes(payload)
            (directory/'owned-before.bin').write_bytes(before)
            (directory/'owned-after.bin').write_bytes(bytes(uc.mem_read(base,36864)))
            if image[0] is not None:(directory/'loaded-bootstrap.bin').write_bytes(image[0])
            data=dict(phase=phase,physical=physical,original_sg=OLD,initial_marker=initial,
                context=context,fail=fail,marker_after=marker_after,reset_readback=readback,
                wrong_p=wrong_p,clock_values=clock_values,clock_step=clock_step,
                clear_x=clear_x,mutate=mutate,frequency=frequency,
                result=result['result'],events=events,ram_reads=ram_reads,stores=stores,
                marker_reads=polls[0],clock_calls=clocks[0],
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                independent_owned_model=True,physical_bootstrap_hardware_qualified=False)
            (directory/'context.json').write_text(json.dumps(data,indent=2)+'\n')
        return result

    def test_separate_preflight_start_observe_across_three_aligned_ram_placements(self):
        for physical in (0x180000,0x290000,0x3e88000):
            for initial in (0,INITIAL):
                preflight=self.execute('preflight',physical,initial=initial);self.assertEqual(preflight['result'],initial);self.assertEqual(preflight['stores'],[])
                start=self.execute('start',physical,initial=initial);self.assertEqual(start['result'],3)
                at=next(i for i,e in enumerate(start['events']) if e[0]=='write')
                self.assertEqual(start['events'][at:],[('write',0xfe83fffc,3),('read',0xfe83fffc)])
                for delay in (1,17):
                    observed=self.execute('observe',physical,marker_after=delay,clear_x=True,initial=initial)
                    self.assertEqual(observed['result'],0xd5000000|delay);self.assertEqual(observed['stores'],[])
                    self.assertEqual(sum(e[0]=='read' and 0xfe83a000<=e[1]<=0xfe83bffc for e in observed['events']),2048)

    def test_any_unexpected_reset_readback_is_exact_and_has_no_followup_operation(self):
        for raw in (0,1,7,0xffffffff,0x80000003,0xdf200004):
            result=self.execute(readback=raw);self.assertEqual(result['result'],raw)
            at=next(i for i,e in enumerate(result['events']) if e[0]=='write')
            self.assertEqual(result['events'][at:],[('write',0xfe83fffc,3),('read',0xfe83fffc)])

    def test_mapping_api_protection_extent_failures_precede_owned_ram_access_or_start(self):
        for fail,stage in (('missing-clock',2),('boolean-calibration',3),('mapping',4),('physical',5),('protect',6),('extent',7)):
            result=self.execute(fail=fail);self.assertEqual(result['result'],0xdf200000|stage)
            self.assertEqual(result['ram_reads'],[]);self.assertEqual(result['stores'],[])

    def test_provenance_table_and_image_corruption_prevent_start(self):
        for offset,value,stage in ((32768,0,8),(32776,OLD+16384,8),(0,0x3fff000,9),
                                   (1544*8+4,1,9),(16384+20,0,10),(32764,0,10)):
            result=self.execute(mutate={offset:value});self.assertEqual(result['result'],0xdf200000|stage)
            self.assertEqual(result['stores'],[])

    def test_current_pointer_max_quiet_reset_marker_and_late_context_guards(self):
        for a,v in ((0xfe83fffc,3),(0xfe802040,0x182000),(0xfe8020d4,1),
                    (0xfe801004,1),(0xfe802000,15),(0xfe801100,0),(0xfe801000,1),(0xfd6806a0,0)):
            result=self.execute(context={a:v});self.assertEqual(result['result'],0xdf200001);self.assertEqual(result['stores'],[])
        for phase in ('preflight','start'):
            for marker in (TOKEN,0xff000001):
                result=self.execute(phase,context={0xfe830400:marker});self.assertEqual(result['result'],0xdf20000d);self.assertEqual(result['stores'],[])
        result=self.execute(context={0xfe830400:INITIAL^1});self.assertEqual(result['result'],0xdf20000d);self.assertEqual(result['stores'],[])
        result=self.execute(fail='context-drift');self.assertEqual(result['result'],0xdf20000c);self.assertEqual(result['stores'],[])

    def test_wrong_frequency_stalled_backward_or_overlong_preflight_clocks_never_start(self):
        for options,stage in ((dict(frequency=0),2),(dict(clock_step=0),11),
                              (dict(clock_values=[100,99]),11),(dict(clock_step=3375001),11)):
            result=self.execute(**options);self.assertEqual(result['result'],0xdf200000|stage);self.assertEqual(result['stores'],[])

    def test_readonly_observer_requires_running_owned_context_and_exact_loaded_extent(self):
        result=self.execute('observe',context={0xfe83fffc:0});self.assertEqual(result['result'],0xdf200001);self.assertEqual(result['stores'],[])
        for index in (0,5,1023,2047):
            result=self.execute('observe',wrong_p=index);self.assertEqual(result['result'],0xdf210000|index);self.assertEqual(result['stores'],[])
        result=self.execute('observe',fail='unexpected-marker');self.assertEqual(result['result'],0xdf20000e);self.assertEqual(result['stores'],[])

    def test_time_count_and_backward_bounds_never_reset_restore_or_free(self):
        for options,stage in ((dict(clock_step=33750),16),(dict(clock_values=[100,101,100]),15),
                              (dict(clock_values=[100,101]),17)):
            result=self.execute('observe',marker_after=None,**options)
            self.assertEqual(result['result'],0xdf200000|stage);self.assertEqual(result['stores'],[])
            self.assertLessEqual(result['marker_reads'],100000)

    def test_actual_owned_image_executes_only_the_marker_then_stop_on_pinned_dsp(self):
        checker=os.environ.get('PROBE_DSP_BOOT_CHECK')
        if not checker:self.skipTest('set PROBE_DSP_BOOT_CHECK to offline pinned checker')
        start=self.execute()
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/'owned-marker.bin'
            full=start['ram'][0x4000:0x8000];self.assertEqual(full[:8192],start['image'])
            image.write_bytes(full)
            run=subprocess.run([checker,str(image)],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr);self.assertIn('no peripheral access',run.stdout)
            positive=dict(returncode=run.returncode,stdout=run.stdout,stderr=run.stderr)
            wrong=bytearray(full);struct.pack_into('<I',wrong,4,0xfd);image.write_bytes(wrong)
            run=subprocess.run([checker,str(image)],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(run.returncode,0)
            artifact_dir=os.environ.get('PROBE_GP_MARKER_ARTIFACT_DIR')
            if artifact_dir:
                directory=Path(artifact_dir)/'actual-dsp';directory.mkdir()
                (directory/'owned-p-image.bin').write_bytes(full)
                (directory/'wrong-marker-target.bin').write_bytes(wrong)
                (directory/'result.json').write_text(json.dumps(dict(positive=positive,
                    negative=dict(returncode=run.returncode,stdout=run.stdout,stderr=run.stderr),
                    actual_pinned_cpu=True,hardware_bootstrap=False),indent=2)+'\n')

    def test_builder_closed_phase_and_exact_source_marker_address_guards(self):
        for args in (('unknown',0x180000,OLD),('start',0x3e8a000,OLD,INITIAL),
                     ('start',True,OLD,INITIAL),('start',0x180000,0x180000,INITIAL),
                     ('start',0x180000,OLD,TOKEN),('start',0x180000,OLD,0x1000000),
                     ('start',0x180000,OLD,None),('preflight',0x180000,OLD,INITIAL)):
            with self.assertRaises(ValueError):compile_marker(*args)
        for phase in ('preflight','start','observe'):self.assertLessEqual(len(code(phase,0x180000)),4096)


if __name__=='__main__':unittest.main()
