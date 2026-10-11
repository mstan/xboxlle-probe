"""Actual low-RAM x86 stages over independent allocator/owner/MMIO models."""
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
from gp_lowram_build import compile_lowram
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ESI,
                              UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)

OLD=0x399c000
TABLE=0xfe802040
BYTES=9*4096


@lru_cache(maxsize=None)
def code(phase,physical):
    return compile_lowram(phase,None if phase=='prepare' else physical,OLD if phase=='calibrate' else None)


def expected_owner(physical):
    words=[0x87]*(BYTES//4)
    for i in range(2048):words[i*2:i*2+2]=[physical+((i+4)*4096 if i<4 else 7*4096),0]
    words[4096:4102]=[0x65f400,0xfc,0x44f400,0x5a34c1,0x21584,0x87]
    words[8192:8196]=[0x47504f31,physical,OLD,0x47504f31^physical^OLD]
    return struct.pack('<9216I',*words)


class LowRamTests(unittest.TestCase):
    def execute(self,phase='prepare',physical=0x180000,prior=None,allocation=None,
                fail=None,readback=None,mutate=None,context=None):
        payload=code(phase,physical)
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        uc.mem_map(0x1000,4096);uc.mem_write(0x1000,payload)
        uc.mem_map(0x5000,4096);uc.mem_map(0x6000,0x3000)
        uc.mem_write(0x8000,struct.pack('<I',0x5000));uc.reg_write(UC_X86_REG_ESP,0x8000)
        uc.mem_map(0x80010000,0x40000);uc.mem_map(0xfd680000,4096)
        uc.mem_map(0xfe801000,0x2000);uc.mem_map(0xfe830000,0x10000)
        def put(a,v):uc.mem_write(a,struct.pack('<I',v))
        uc.mem_write(0x80010000,b'MZ');put(0x8001003c,0x80);put(0x80010080,0x4550)
        uc.mem_write(0x80010098,struct.pack('<H',0x10b));put(0x800100d0,0x40000)
        put(0x800100f8,0x2000);put(0x800100fc,0x1000)
        put(0x80012010,1);put(0x80012014,400);put(0x8001201c,0x2400)
        exports={166:0xa000,173:0xb000,174:0xc000,175:0xd000,179:0xe000,180:0xf000}
        for ordinal,rva in exports.items():put(0x80012400+(ordinal-1)*4,rva)
        if fail=='missing-allocate':put(0x80012400+(166-1)*4,0)
        base=(0x80000000|physical) if allocation is None else allocation
        allocated=[False];pinned=[phase!='prepare'];before=None
        if phase!='prepare':
            uc.mem_map(base,BYTES);uc.mem_write(base,prior);allocated[0]=True
            for offset,value in (mutate or {}).items():put(base+offset,value)
            before=bytes(uc.mem_read(base,BYTES))
        regs={0xfe83fffc:0,0xfe801004:0xafa,0xfe802000:7,0xfe801100:0x71f8f,
              0xfe801000:0,0xfd6806a0:0x11,TABLE:OLD,0xfe8020d4:1544}
        regs.update(context or {})
        events=[];calls=[];reads=[];stores=[];device_stored=[False];owner_read=[False]
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items():uc.reg_write(reg,value)
        def kernel(u,a,size,unused):
            ordinal=next((o for o,r in exports.items() if a==0x80010000+r),None)
            if ordinal is None:return
            self.assertFalse(device_stored[0],'kernel operation after SG store')
            counts={166:5,173:1,174:1,175:3,179:1,180:1};count=counts[ordinal]
            sp=u.reg_read(UC_X86_REG_ESP);args=struct.unpack('<'+'I'*count,u.mem_read(sp+4,count*4))
            calls.append((ordinal,args));events.append(('kernel',ordinal,args))
            if ordinal==166:
                # Independent last-byte derivation, not imported builder bounds.
                self.assertEqual(args,(9*4096,0,0x600000+9*4096-1,4*4096,0x204))
                value=0 if fail=='allocation' else base
                if value:uc.mem_map(base,BYTES);allocated[0]=True
            elif ordinal==174:
                a=args[0];value=int(a==0x80010000 or (allocated[0] and base<=a<base+BYTES))
                if fail=='valid-calibration' and a==0x40000000:value=1
                if fail=='boolean' and a==base:value=2
                if fail=='mapping' and a==base+4096:value=0
                if fail=='post-pin' and pinned[0] and a==base:value=0
                value|=0xabcde000
            elif ordinal==173:
                a=args[0];self.assertTrue(a==0x80010000 or (allocated[0] and base<=a<base+BYTES))
                value=0x10000 if a==0x80010000 else physical+a-base
                if fail=='physical' and a==base+8191:value+=4096
            elif ordinal==179:
                self.assertTrue(base<=args[0]<base+BYTES)
                value=4 if fail=='protect' and args[0]==base+4096 else 0x204
            elif ordinal==180:
                self.assertEqual(args,(base,));value=BYTES-4096 if fail=='extent' else BYTES
            else:
                self.assertEqual(args,(base,BYTES,0));self.assertFalse(owner_read[0])
                pinned[0]=True;value=0
            u.reg_write(UC_X86_REG_EAX,value)
            u.reg_write(UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(UC_X86_REG_ESP,sp+4+count*4)
        def read(u,access,a,size,value,unused):
            if a>=0xfd000000:
                self.assertIn(a,regs);self.assertEqual(size,4)
                if fail=='context-drift' and a==0xfe83fffc and sum(e==('read',a) for e in events):regs[a]=3
                events.append(('read',a));put(a,regs[a])
            elif base<=a<base+BYTES:
                self.assertFalse(device_stored[0]);self.assertEqual(size,4)
                self.assertTrue(pinned[0]);owner_read[0]=True;reads.append(a-base)
        def write(u,access,a,size,value,unused):
            if a>=0xfd000000:
                self.assertEqual((phase,a,size,value),('calibrate',TABLE,4,physical))
                self.assertFalse(device_stored[0]);device_stored[0]=True
                events.append(('write',a,value));regs[a]=value if readback is None else readback
            elif base<=a<base+BYTES:
                self.assertEqual(phase,'prepare');self.assertEqual(size,4);self.assertTrue(pinned[0])
                self.assertTrue(physical and physical<=0x600000 and physical%16384==0)
                stores.append((a-base,value))
            else:self.assertTrue(0x6000<=a and a+size<=0x8000,'unowned CPU store')
        uc.hook_add(UC_HOOK_CODE,kernel);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x5000,count=1000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x5000);self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        ram=bytes(uc.mem_read(base,BYTES)) if allocated[0] else None
        if phase!='prepare':self.assertEqual(ram,before)
        result=dict(result=uc.reg_read(UC_X86_REG_EAX),events=events,calls=calls,
            reads=reads,stores=stores,pinned=pinned[0],ram=ram)
        artifact_dir=os.environ.get('PROBE_GP_LOWRAM_ARTIFACT_DIR')
        if artifact_dir:
            folder=Path(artifact_dir)/f'context-{len(list(Path(artifact_dir).glob("context-*"))):03d}';folder.mkdir()
            (folder/'payload.bin').write_bytes(payload)
            if before is not None:(folder/'owned-before.bin').write_bytes(before)
            if ram is not None:(folder/'owned-after.bin').write_bytes(ram)
            data=dict(phase=phase,physical=physical,allocation=allocation,fail=fail,readback=readback,
                mutate=mutate,context=context,result=result['result'],events=events,
                calls=calls,reads=reads,stores=stores,pinned=pinned[0],
                payload_sha256=hashlib.sha256(payload).hexdigest(),independent_model=True,
                hardware_or_network_operations=0)
            (folder/'context.json').write_text(json.dumps(data,indent=2)+'\n')
        return result

    def prepared(self,physical=0x180000):
        result=self.execute(physical=physical)
        self.assertEqual(result['result'],0xd4000000|physical)
        self.assertEqual(result['ram'],expected_owner(physical))
        self.assertTrue(result['pinned']);self.assertFalse(any(e[0]=='write' for e in result['events']))
        return result

    def test_three_complete_lifetimes_including_exact_endpoint_and_real_discrimination_backing(self):
        for physical in (0x4000,0x180000,0x600000):
            produced=self.prepared(physical);prior=produced['ram']
            observed=self.execute('inspect',physical,prior);self.assertEqual(observed['result'],OLD)
            calibrated=self.execute('calibrate',physical,prior);self.assertEqual(calibrated['result'],physical)
            at=next(i for i,e in enumerate(calibrated['events']) if e[0]=='write')
            self.assertEqual(calibrated['events'][at:],[('write',TABLE,physical),('read',TABLE)])
            self.assertFalse(any(o in (166,175) for o,a in observed['calls']+calibrated['calls']))
            self.assertTrue(all(not ((0x80000000|OLD)<=a<(0x80000000|OLD)+16384)
                for o,args in produced['calls']+observed['calls']+calibrated['calls'] for a in args))
            # At600000 the two plausible addresses are606000 and607000, both
            # genuine owned pages; the normal SG index1542 remains <=1544.
            field=physical+6*4096;index=field//4096
            page,pad=struct.unpack_from('<II',prior,index*8)
            self.assertLessEqual(index,1544);self.assertEqual((page,pad),(physical+7*4096,0))
            self.assertNotEqual(field,page);self.assertLess(field+4095,physical+BYTES)

    def test_no_space_missing_allocator_high_unaligned_zero_and_wrong_alias_fail_before_ram(self):
        for options,stage in ((dict(fail='allocation'),5),(dict(fail='missing-allocate'),3),
            (dict(physical=0x604000),7),(dict(physical=0x3e88000),7),
            (dict(physical=0x3e8a000),7),(dict(physical=0x601000),7),
            (dict(physical=0),7),(dict(allocation=0x90180000),7)):
            result=self.execute(**options);self.assertEqual(result['result'],0xdf300000|stage)
            self.assertEqual(result['reads'],[]);self.assertEqual(result['stores'],[])
            self.assertFalse(any(e[0]=='write' for e in result['events']))
            if options.get('fail')=='allocation':
                at=next(i for i,e in enumerate(result['events']) if e[0]=='kernel' and e[1]==166)
                self.assertEqual(len(result['events']),at+1)

    def test_boolean_mapping_physical_protection_extent_and_post_pin_fail_before_owned_access(self):
        for fail,stage in (('valid-calibration',4),('boolean',6),('mapping',8),
                           ('physical',9),('protect',10),('extent',11),('post-pin',12)):
            result=self.execute(fail=fail);self.assertEqual(result['result'],0xdf300000|stage)
            self.assertEqual(result['reads'],[]);self.assertEqual(result['stores'],[])
            self.assertFalse(any(e[0]=='write' for e in result['events']))

    def test_retained_ownership_faults_and_provenance_table_stop_corruption_never_store_sg(self):
        prior=self.prepared()['ram']
        for phase in ('inspect','calibrate'):
            for fail,stage in (('mapping',8),('physical',9),('protect',10),('extent',11)):
                result=self.execute(phase,prior=prior,fail=fail)
                self.assertEqual(result['result'],0xdf300000|stage);self.assertEqual(result['reads'],[])
                self.assertEqual(result['stores'],[]);self.assertFalse(any(e[0]=='write' for e in result['events']))
        for offset,value,stage in ((32768,0,13),(32772,0x184000,13),(32776,OLD+16384,13),
            (32780,0,13),(0,0x3fff000,14),(1544*8+4,1,14),(16384+20,0,15),(32764,0,15)):
            result=self.execute('calibrate',prior=prior,mutate={offset:value})
            self.assertEqual(result['result'],0xdf300000|stage)
            self.assertFalse(any(e[0]=='write' for e in result['events']))

    def test_quiet_context_before_allocation_and_handoff_drift_preserve_retained_owner(self):
        for address,value in ((0xfe83fffc,3),(0xfe801004,0),(0xfe802000,15),
            (0xfe801100,0),(0xfe801000,1),(0xfd6806a0,0),(TABLE,0),(TABLE,OLD+1),(0xfe8020d4,1)):
            result=self.execute(context={address:value})
            self.assertIn(result['result'],(0xdf300001,0xdf300002));self.assertEqual(result['calls'],[])
            self.assertEqual(result['stores'],[])
        prior=self.prepared()['ram']
        result=self.execute('calibrate',prior=prior,fail='context-drift')
        self.assertEqual(result['result'],0xdf300010);self.assertEqual(result['ram'],prior)
        self.assertFalse(any(e[0]=='write' for e in result['events']))

    def test_raw_unexpected_sg_readback_ends_immediately_without_kernel_ram_or_device_followup(self):
        prior=self.prepared(0x600000)['ram']
        for raw in (0,OLD,0x3e88000,0x600001,0xffffffff,0xdf300005):
            result=self.execute('calibrate',0x600000,prior,readback=raw)
            self.assertEqual(result['result'],raw);self.assertEqual(result['ram'],prior)
            at=next(i for i,e in enumerate(result['events']) if e[0]=='write')
            self.assertEqual(result['events'][at:],[('write',TABLE,0x600000),('read',TABLE)])

    def test_closed_builder_rejects_high_or_inexact_addresses_without_high_ram_fallback(self):
        for args in (('unknown',),('prepare',0x180000),('inspect',None),('inspect',True),
            ('inspect',0),('inspect',0x601000),('inspect',0x604000),('inspect',0x3e88000),
            ('inspect',0x180000,OLD),('calibrate',0x180000,None),
            ('calibrate',0x180000,0x180000),('calibrate',0x180000,OLD+1)):
            with self.assertRaises(ValueError):compile_lowram(*args)
        for phase in ('prepare','inspect','calibrate'):self.assertLessEqual(len(code(phase,0x600000)),4096)


if __name__=='__main__':unittest.main()
