"""Execute the actual compiled payload with independent PE/API/device models."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
import observe_fe_fence as fence
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ESI,UC_X86_REG_EDI,
                              UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)


class FenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.code=fence.compiled_payload()

    def execute(self,initial=1,malformed=None,allocation=0x80180000,physical=0x180000,
                token_after=1,wrong_token=False,ignore_restore=False,changed_control=None):
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,self.code)
        uc.mem_map(0x7000,0x2000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
        uc.reg_write(UC_X86_REG_ESP,0x8000)
        uc.mem_map(0x80010000,0x40000);uc.mem_map(0xfe801000,0x1000)
        def word(address,value):uc.mem_write(address,struct.pack('<I',value))
        uc.mem_write(0x80010000,b'MZ');word(0x8001003c,0x80)
        word(0x80010080,0x4550);uc.mem_write(0x80010098,struct.pack('<H',0x10b))
        word(0x800100d0,0x40000);word(0x800100f8,0x2000);word(0x800100fc,0x1000)
        word(0x80012010,1);word(0x80012014,400);word(0x8001201c,0x2400)
        word(0x80012400+165*4,0xa000);word(0x80012400+172*4,0xb000)
        if malformed:
            mutations=malformed if isinstance(malformed,list) else [malformed]
            for location,value in mutations:word(location,value)
        preserved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
                   UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in preserved.items():uc.reg_write(reg,value)
        calls=[];stores=[];cpu_scratch=[];reads=[];control=[initial];submitted=[False];polls=[0]
        def function(u,address,size,data):
            if address not in (0x8001a000,0x8001b000):return
            sp=u.reg_read(UC_X86_REG_ESP)
            if address==0x8001a000:
                args=struct.unpack('<5I',u.mem_read(sp+4,20));calls.append(('allocate',args))
                self.assertEqual(args,(4096,0,0x3ffffff,4096,0x204))
                if allocation:u.mem_map(allocation,4096)
                result=allocation;cleanup=24
            else:
                args=struct.unpack('<I',u.mem_read(sp+4,4));calls.append(('physical',args))
                self.assertEqual(args,(allocation,));result=physical;cleanup=8
            return_address=struct.unpack('<I',u.mem_read(sp,4))[0]
            u.reg_write(UC_X86_REG_EAX,result);u.reg_write(UC_X86_REG_ESP,sp+cleanup)
            u.reg_write(UC_X86_REG_EIP,return_address)
        def read(u,access,address,size,value,data):
            if address==0xfe801510:
                reads.append(address);word(address,control[0])
            elif address==allocation and allocation:
                if submitted[0]:
                    polls[0]+=1
                    if changed_control is not None:control[0]=changed_control
                    if token_after is not None and polls[0]>=token_after:
                        word(address,0xdeadbeef if wrong_token else 0x5a34f00e)
            elif 0xfe800000 <= address < 0xff000000:self.fail('unapproved device read')
        def write(u,access,address,size,value,data):
            if 0xfe800000 <= address < 0xff000000:
                self.assertIn(address,(0xfe801510,0xfe801324,0xfe801334));self.assertEqual(size,4)
                stores.append((address,value))
                if address==0xfe801510:
                    if not (ignore_restore and submitted[0]):control[0]=value
                    if value==0:submitted[0]=True
                elif address==0xfe801324:self.assertEqual(value,physical)
                elif address==0xfe801334:self.assertEqual(value,0x5a34f00e)
            elif allocation and address==allocation:
                cpu_scratch.append(value);self.assertEqual(value,0xa5cb0ff1)
            else:
                self.assertGreaterEqual(address,0x7000);self.assertLess(address+size,0x8001)
        uc.hook_add(UC_HOOK_CODE,function);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x1800,count=2000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x1800,'payload did not return within instruction bound')
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in preserved.items():self.assertEqual(uc.reg_read(reg),value)
        return dict(result=uc.reg_read(UC_X86_REG_EAX),control=control[0],calls=calls,stores=stores,
                    cpu_scratch=cpu_scratch,polls=polls[0])

    def test_actual_immediate_and_delayed_ram_visibility(self):
        for delay in (1,2,17,100000):
            result=self.execute(token_after=delay)
            self.assertEqual(result['result'],0xf1000000|delay)
            self.assertEqual(result['control'],1)
            self.assertEqual(result['stores'],[(0xfe801510,1),(0xfe801324,0x180000),
                                              (0xfe801334,0x5a34f00e),(0xfe801510,0),(0xfe801510,1)])
            self.assertEqual(result['cpu_scratch'],[0xa5cb0ff1])
            self.assertEqual([name for name,args in result['calls']],['allocate','physical'])

    def test_initial_control_cannot_allocate_or_write(self):
        for control in (0,2,0xffffffff):
            result=self.execute(initial=control)
            self.assertEqual(result['result'],0xfa000001);self.assertEqual(result['stores'],[])
            self.assertEqual(result['calls'],[])

    def test_malformed_pe_never_calls_kernel_or_device(self):
        for mutation in ((0x80010000,0),(0x8001003c,0x100000),(0x80010080,0),
                         (0x80010098,0x20b),(0x800100d0,0xffffffff),
                         (0x800100f8,0x3fffe),(0x800100fc,0xffffffff),
                         (0x80012010,174),(0x80012014,4097),(0x8001201c,0x40000),
                         (0x80012400+165*4,0x2004),
                         [(0x800100d0,0x3000),(0x80012014,4096)]):
            result=self.execute(malformed=mutation)
            self.assertEqual(result['result'],0xfa000002)
            self.assertEqual(result['calls'],[]);self.assertEqual(result['stores'],[])

    def test_allocation_and_physical_mismatch_have_no_apu_write(self):
        for kwargs,code in ((dict(allocation=0),0xfa000003),
                            (dict(allocation=0x90180000),0xfa000004),
                            (dict(physical=0),0xfa000004),(dict(physical=0x180004),0xfa000004),
                            (dict(physical=0x4000000),0xfa000004)):
            result=self.execute(**kwargs)
            self.assertEqual(result['result'],code);self.assertEqual(result['stores'],[])

    def test_timeout_retains_page_and_is_not_success(self):
        result=self.execute(token_after=None)
        self.assertEqual(result['result'],0xf2000000|100001);self.assertEqual(result['control'],1)
        self.assertLessEqual(result['polls'],100001)
        self.assertEqual([name for name,args in result['calls']],['allocate','physical'])

    def test_wrong_device_value_or_failed_restore_cannot_qualify(self):
        self.assertEqual(self.execute(wrong_token=True)['result']>>24,0xf2)
        self.assertEqual(self.execute(ignore_restore=True)['result'],0xfa000006)
        result=self.execute(changed_control=8)
        self.assertEqual(result['result'],0xfa000006)
        self.assertEqual(result['stores'][-1],(0xfe801510,9))

    def host(self,reply='RET f1000001',risk=True,identity='PONG xboxlle-probe v0.4.0'):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'session';calls=[]
            class Agent:
                def __init__(self,host,timeout):pass
                def request(self,command,**kwargs):
                    calls.append((command,kwargs))
                    if command=='PING':return identity
                    if isinstance(reply,Exception):raise reply
                    return reply
            with patch.object(fence,'compiled_payload',return_value=self.code),patch.object(fence,'AgentClient',Agent),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                try:result=fence.run(argparse.Namespace(host='127.0.0.1',output=output,i_accept_the_risk=risk))
                except fence.ProbeError:result=3
            return result,calls,{p.name:p.read_text() for p in output.glob('*')}

    def test_host_single_arm_path_and_bounds(self):
        result,calls,files=self.host();self.assertEqual(result,0);self.assertEqual(len(calls),2)
        self.assertEqual(calls[1],('EXEC '+str(len(self.code)),dict(payload=self.code,dangerous=True)))
        self.assertEqual(json.loads(files['summary.json'])['retained_owned_scratch_bytes'],4096)

    def test_host_failures_stop_and_keep_reply(self):
        result,calls,_=self.host(risk=False);self.assertEqual(result,3);self.assertEqual(calls,[])
        result,calls,_=self.host(identity='PONG xlle-agent v0.2');self.assertEqual(result,2);self.assertEqual(len(calls),1)
        for bad in ('RET f2000001','RET fa000006','RET f1000000','RET f10186a1',
                    'RET f1fe0001','RET 100000000','ERR denied',OSError('timeout')):
            result,calls,files=self.host(reply=bad)
            self.assertEqual(result,2);self.assertEqual(len(calls),2)
            self.assertNotIn('summary.json',files)
            if isinstance(bad,str):self.assertIn(bad,files['reply.txt'])


if __name__=='__main__':unittest.main()
