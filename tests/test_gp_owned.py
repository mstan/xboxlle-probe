"""Execute the actual closed x86 stages without networking or an Xbox."""
from functools import lru_cache
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
from gp_owned_build import compile_owned, authored_b3_image, BYTES
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ESI,
                              UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

OLD=0x399c000
TABLE=0xfe802040


@lru_cache(maxsize=None)
def code(phase, physical=0x180000, old=OLD):
    return compile_owned(phase, None if phase=='prepare' else physical,
                         old if phase=='calibrate' else None)


class OwnedTests(unittest.TestCase):
    def execute(self, phase='prepare', physical=0x180000, prior=None,
                allocation=None, fail=None, readback=None, mutate=None, context=None):
        program=code(phase,physical)
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        uc.mem_map(0x1000,4096);uc.mem_write(0x1000,program)
        uc.mem_map(0x5000,4096)
        uc.mem_map(0x6000,0x3000);uc.mem_write(0x8000,struct.pack('<I',0x5000))
        uc.reg_write(UC_X86_REG_ESP,0x8000)
        uc.mem_map(0x80010000,0x40000);uc.mem_map(0xfd680000,4096)
        uc.mem_map(0xfe801000,0x2000);uc.mem_map(0xfe830000,0x10000)
        def put(a,v): uc.mem_write(a,struct.pack('<I',v))
        uc.mem_write(0x80010000,b'MZ');put(0x8001003c,0x80)
        put(0x80010080,0x4550);uc.mem_write(0x80010098,struct.pack('<H',0x10b))
        put(0x800100d0,0x40000);put(0x800100f8,0x2000);put(0x800100fc,0x1000)
        put(0x80012010,1);put(0x80012014,400);put(0x8001201c,0x2400)
        exports={166:0xa000,173:0xb000,174:0xc000,175:0xd000,179:0xe000,180:0xf000}
        for ordinal,rva in exports.items(): put(0x80012400+(ordinal-1)*4,rva)
        base=(0x80000000|physical) if allocation is None else allocation
        if phase!='prepare':
            uc.mem_map(base,BYTES);uc.mem_write(base,prior)
            if mutate:
                for offset,value in mutate.items(): put(base+offset,value)
        regs={0xfe83fffc:0,TABLE:OLD,0xfe8020d4:1544,0xfe801004:0xafa,
              0xfe802000:7,0xfe801100:0x71f8f,0xfe801000:0,0xfd6806a0:0x11}
        regs.update(context or {})
        calls=[];accesses=[];ram_reads=[];ram_stores=[];pinned=[False];allocated=[phase!='prepare']
        has_device_store=[False]
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items(): uc.reg_write(reg,value)
        def kernel(u,a,size,unused):
            ordinal=next((o for o,r in exports.items() if a==0x80010000+r),None)
            if ordinal is None:return
            self.assertFalse(has_device_store[0],'kernel call after device readback')
            sp=u.reg_read(UC_X86_REG_ESP);counts={166:5,173:1,174:1,175:3,179:1,180:1}
            args=struct.unpack('<'+'I'*counts[ordinal],u.mem_read(sp+4,counts[ordinal]*4))
            calls.append((ordinal,args))
            if ordinal==166:
                self.assertEqual(args,(BYTES,0,0x3ffffff,16384,0x204))
                value=0 if fail=='allocation' else base
                if value: u.mem_map(base,BYTES);allocated[0]=True
            elif ordinal==174:
                a=args[0]
                value=int(a==0x80010000 or (allocated[0] and base<=a<base+BYTES))
                if fail=='valid-calibration' and a==0x40000000:value=1
                if fail=='boolean' and a==base:value=2
                if fail=='mapping' and a==base+4096:value=0
                if fail=='post-pin' and pinned[0] and a==base:value=0
                value|=0xabcde000 # upper EAX bits are unspecified for BOOLEAN.
            elif ordinal==173:
                a=args[0]
                self.assertTrue(a==0x80010000 or (allocated[0] and base<=a<base+BYTES))
                value=0x10000 if a==0x80010000 else physical+(a-base)
                if fail=='physical-calibration' and a==0x80010000:value=0x20000
                if fail=='physical' and a==base+8191:value+=4096
            elif ordinal==179:
                self.assertTrue(base<=args[0]<base+BYTES)
                value=0x204
                if fail=='protect' and args[0]==base+4096:value=0x4
            elif ordinal==180:
                self.assertEqual(args,(base,));value=BYTES-4096 if fail=='extent' else BYTES
            else:
                self.assertEqual(args,(base,BYTES,0));pinned[0]=True;value=0
            u.reg_write(UC_X86_REG_EAX,value)
            u.reg_write(UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0])
            u.reg_write(UC_X86_REG_ESP,sp+4+counts[ordinal]*4)
        def read(u,access,a,size,value,unused):
            if a>=0xfd000000:
                self.assertIn(a,regs);self.assertEqual(size,4)
                if fail=='context-drift' and a==0xfe83fffc and accesses:
                    regs[a]=3
                accesses.append(('read',a))
                put(a,regs[a])
            elif base<=a<base+BYTES:
                self.assertEqual(size,4);ram_reads.append(a-base)
                if phase=='prepare':self.assertTrue(pinned[0],'RAM read precedes pin')
        def write(u,access,a,size,value,unused):
            if a>=0xfd000000:
                self.assertEqual(phase,'calibrate');self.assertEqual(a,TABLE);self.assertEqual(size,4)
                self.assertFalse(has_device_store[0]);has_device_store[0]=True
                accesses.append(('write',a,value));regs[a]=value if readback is None else readback
            elif base<=a<base+BYTES:
                self.assertEqual(phase,'prepare');self.assertTrue(pinned[0]);self.assertEqual(size,4)
                ram_stores.append((a-base,value))
            else:
                self.assertTrue(0x6000<=a and a+size<=0x8000,'unowned CPU store')
        uc.hook_add(UC_HOOK_CODE,kernel);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x5000,count=1000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x5000)
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        return dict(result=uc.reg_read(UC_X86_REG_EAX),calls=calls,accesses=accesses,
                    reads=ram_reads,stores=ram_stores,pinned=pinned[0],
                    ram=bytes(uc.mem_read(base,BYTES)) if allocated[0] else None)

    def prepared(self,physical=0x180000):
        result=self.execute(physical=physical)
        self.assertEqual(result['result']&0xfc000000,0xd4000000)
        self.assertEqual(result['result']&0x03ffffff,physical)
        return result

    def test_three_real_owned_lifetimes_and_independent_exact_layout(self):
        for physical in (0x180000,0x294000,0x3210000):
            result=self.prepared(physical)
            self.assertTrue(result['pinned']);self.assertFalse(any(a[0]=='write' for a in result['accesses']))
            data=result['ram'];words=struct.unpack('<9216I',data)
            for i in range(2048):
                self.assertEqual(words[2*i:2*i+2],(physical+((i+4)*4096 if i<4 else 7*4096),0))
            self.assertEqual(words[4096:4102],(0x65f400,0xfc,0x44f400,0x5a34c1,0x21584,0x87))
            self.assertEqual(words[4102:8192],(0x87,)*(8192-4102))
            self.assertEqual(words[8192:8196],(0x47504f31,physical,OLD,0x47504f31^physical^OLD))
            self.assertEqual(words[8196:],(0x87,)*(9216-8196))
            # No inherited CPU alias is ever passed to a memory API or loaded.
            self.assertFalse(any((0x80000000|OLD)<=arg<(0x80000000|OLD)+16384
                                 for ordinal,args in result['calls'] for arg in args))

    def test_prepare_then_readonly_inspect_then_one_exact_calibration(self):
        for physical in (0x180000,0x294000,0x3210000):
            prior=self.prepared(physical)['ram']
            observed=self.execute('inspect',physical,prior)
            self.assertEqual(observed['result'],OLD);self.assertEqual(observed['ram'],prior)
            self.assertFalse(any(a[0]=='write' for a in observed['accesses']))
            calibrated=self.execute('calibrate',physical,prior)
            self.assertEqual(calibrated['result'],physical);self.assertEqual(calibrated['ram'],prior)
            at=next(i for i,a in enumerate(calibrated['accesses']) if a[0]=='write')
            self.assertEqual(calibrated['accesses'][at:],[('write',TABLE,physical),('read',TABLE)])
            self.assertFalse(any(c[0] in (166,175) for c in calibrated['calls']))

    def test_unexpected_write_returns_the_exact_word_and_performs_nothing_further(self):
        prior=self.prepared()['ram']
        for readback in (OLD,0,0xffffffff,0x180001,0x180,0x80000000):
            result=self.execute('calibrate',prior=prior,readback=readback)
            self.assertEqual(result['result'],readback);self.assertEqual(result['ram'],prior)
            at=next(i for i,a in enumerate(result['accesses']) if a[0]=='write')
            self.assertEqual(result['accesses'][at:],[('write',TABLE,0x180000),('read',TABLE)])

    def test_allocation_mapping_physical_protect_extent_and_pin_fail_before_ram_load(self):
        cases={'allocation':5,'boolean':6,'mapping':8,'physical':9,'protect':10,
               'extent':11,'post-pin':12,'valid-calibration':4,'physical-calibration':4}
        for fail,stage in cases.items():
            result=self.execute(fail=fail)
            self.assertEqual(result['result'],0xdf100000|stage)
            self.assertEqual(result['reads'],[]);self.assertEqual(result['stores'],[])
            self.assertFalse(any(a[0]=='write' for a in result['accesses']))

    def test_contexts_are_checked_before_allocation(self):
        for address,value in ((0xfe83fffc,3),(0xfe801004,0),(0xfe802000,15),
                              (0xfe801100,0),(0xfe801000,1),(0xfd6806a0,0),
                              (TABLE,0),(TABLE,OLD+1),(0xfe8020d4,1)):
            result=self.execute(context={address:value})
            self.assertIn(result['result'],(0xdf100001,0xdf100002))
            self.assertEqual(result['calls'],[]);self.assertEqual(result['stores'],[])

    def test_later_mapping_or_protection_failure_has_no_owned_ram_load_or_device_store(self):
        prior=self.prepared()['ram']
        for phase in ('inspect','calibrate'):
            for fail in ('mapping','physical','protect','extent'):
                result=self.execute(phase,prior=prior,fail=fail)
                self.assertEqual(result['reads'],[]);self.assertEqual(result['stores'],[])
                self.assertFalse(any(a[0]=='write' for a in result['accesses']))

    def test_corrupt_provenance_sge_or_boot_image_cannot_reach_calibration(self):
        prior=self.prepared()['ram']
        for offset,value in ((32768,0),(32772,0),(32776,OLD+4096),(32780,0),
                             (0,0x3fff000),(12,1),(1544*8,0),(16384+20,0)):
            result=self.execute('calibrate',prior=prior,mutate={offset:value})
            self.assertIn(result['result'],(0xdf10000d,0xdf10000e,0xdf10000f))
            self.assertFalse(any(a[0]=='write' for a in result['accesses']))

    def test_actual_unaligned_address_is_rejected_before_ram_or_device_access(self):
        # The real old calibration requested03E8A000 and returned03E88000.
        # Preserve exact-address checks; never treat rounded storage as owned.
        for physical in (0x03e8a000,0x181000,0x182000):
            result=self.execute(physical=physical)
            self.assertEqual(result['result'],0xdf100007)
            self.assertEqual(result['reads'],[]);self.assertEqual(result['stores'],[])
            self.assertFalse(any(a[0]=='write' for a in result['accesses']))
            for phase in ('inspect','calibrate'):
                with self.assertRaises(ValueError):
                    compile_owned(phase,physical,OLD if phase=='calibrate' else None)

    def test_wrong_allocator_alias_is_rejected_without_loading_it(self):
        result=self.execute(allocation=0x90180000)
        self.assertEqual(result['result'],0xdf100007);self.assertEqual(result['reads'],[])
        self.assertEqual(result['stores'],[])

    def test_handoff_context_drift_retains_ram_without_a_device_store(self):
        prior=self.prepared()['ram']
        result=self.execute('calibrate',prior=prior,fail='context-drift')
        self.assertEqual(result['result'],0xdf100010);self.assertEqual(result['ram'],prior)
        self.assertFalse(any(a[0]=='write' for a in result['accesses']))
        changed=self.execute('calibrate',prior=prior,context={TABLE:OLD+16384})
        self.assertEqual(changed['result'],0xdf10000d)
        self.assertFalse(any(a[0]=='write' for a in changed['accesses']))

    def test_builder_accepts_only_closed_bounded_stages(self):
        for args in (('unknown',),('prepare',0x180000),('inspect',None),('inspect',True),
                     ('inspect',0),('inspect',0x180001),('inspect',0x3ff8000),
                     ('inspect',0x180000,OLD),('calibrate',0x180000,None),
                     ('calibrate',0x180000,0x180000),('calibrate',0x180000,OLD+1)):
            with self.assertRaises(ValueError):compile_owned(*args)
        for phase in ('prepare','inspect','calibrate'):
            self.assertLessEqual(len(code(phase)),4096)

    def test_finite_authored_b3_stimulus_on_the_pinned_actual_dsp_cpu(self):
        checker=os.environ.get('PROBE_B3_CONTEXT_CHECK')
        if not checker:self.skipTest('set PROBE_B3_CONTEXT_CHECK to the offline compiled checker')
        data=authored_b3_image()
        self.assertEqual(len(data),16384)
        self.assertEqual(struct.unpack_from('<I',data,102*4)[0],0x87)
        self.assertEqual(data[103*4:],struct.pack('<I',0x87)*(4096-103))
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/'authored-b3.bin';image.write_bytes(data)
            checked=subprocess.run([checker,str(image)],capture_output=True,text=True,timeout=10)
            self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)
            self.assertIn('3 injected B3 samples',checked.stdout)
            # Independent consumer expects the four exact targets, not the
            # source's claimed list or a manufactured CPU completion marker.
            for offset,value in ((9*4,0x108),(0,0x7f433)):
                wrong=bytearray(data);struct.pack_into('<I',wrong,offset,value)
                image.write_bytes(wrong)
                checked=subprocess.run([checker,str(image)],capture_output=True,text=True,timeout=10)
                self.assertNotEqual(checked.returncode,0)


if __name__=='__main__':unittest.main()
