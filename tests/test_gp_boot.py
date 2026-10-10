"""Actual x86 ownership/stop effects, plus execution of its authored DSP image."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
import observe_gp_boot as observer
from payload_build import compile_fixed
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_EDX,UC_X86_REG_ESI,
                              UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)


class BootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.code=compile_fixed('gp_boot')

    def execute(self,context=None,marker_after=1,clear_x=False,allocation=0x80180000,
                physical=0x180000,frequency=3375000,clock_step=1000,clock_values=None,
                malformed=False,ignore_store=None,wrong_image=False,wrong_marker=False,
                changed_sg=False,changed_reset=False):
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,self.code)
        uc.mem_map(0x6000,0x3000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
        uc.reg_write(UC_X86_REG_ESP,0x8000)
        uc.mem_map(0x80010000,0x40000);uc.mem_map(0xfd680000,0x1000)
        uc.mem_map(0xfe801000,0x2000);uc.mem_map(0xfe830000,0x10000)
        def word(address,value):uc.mem_write(address,struct.pack('<I',value))
        uc.mem_write(0x80010000,b'zz' if malformed else b'MZ');word(0x8001003c,0x80)
        word(0x80010080,0x4550);uc.mem_write(0x80010098,struct.pack('<H',0x10b))
        word(0x800100d0,0x40000);word(0x800100f8,0x2000);word(0x800100fc,0x1000)
        word(0x80012010,1);word(0x80012014,400);word(0x8001201c,0x2400)
        exports={166:0xa000,173:0xb000,126:0xc000,127:0xd000}
        for ordinal,rva in exports.items():word(0x80012400+(ordinal-1)*4,rva)
        registers={0xfe83fffc:0,0xfe802040:0x0399c000,0xfe8020d4:1544,
                   0xfe830400:0x123456,0xfe801004:0xafa,0xfe802000:7,
                   0xfe801100:0x71f8f,0xfe801000:0,0xfd6806a0:0x11}
        registers.update(context or {});original=dict(registers)
        calls=[];stores=[];reads=[];ticks=[1<<40];counter_calls=[0];polls=[0];image=[None]
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items():uc.reg_write(reg,value)
        def kernel(u,address,size,data):
            if address not in (0x8001a000,0x8001b000,0x8001c000,0x8001d000):return
            sp=u.reg_read(UC_X86_REG_ESP);cleanup=4
            if address==0x8001a000:
                args=struct.unpack('<5I',u.mem_read(sp+4,20));calls.append(('allocate',args))
                self.assertEqual(args,(28672,0,0x3ffffff,4096,0x204))
                if allocation:u.mem_map(allocation,28672)
                value=allocation;cleanup=24
            elif address==0x8001b000:
                args=struct.unpack('<I',u.mem_read(sp+4,4));calls.append(('physical',args))
                self.assertEqual(args,(allocation,));value=physical;cleanup=8
            elif address==0x8001d000:calls.append(('frequency',()));value=frequency
            else:
                index=counter_calls[0];counter_calls[0]+=1
                if clock_values is not None:value=clock_values[min(index,len(clock_values)-1)]
                else:ticks[0]+=clock_step;value=ticks[0]
            u.reg_write(UC_X86_REG_EAX,value&0xffffffff);u.reg_write(UC_X86_REG_EDX,value>>32)
            u.reg_write(UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(UC_X86_REG_ESP,sp+cleanup)
        def read(u,access,address,size,value,data):
            if address<0xfd000000:return
            self.assertEqual(size,4);reads.append(address)
            if address in registers:
                value=registers[address]
                if address==0xfe830400 and registers[0xfe83fffc]==3:
                    polls[0]+=1
                    if marker_after is not None and polls[0]>=marker_after:
                        value=0xdeadbe if wrong_marker else 0x5a34c1;registers[address]=value
                    elif clear_x:value=0
                if changed_sg and address==0xfe802040 and polls[0]:value=0xffffffff
                if changed_reset and address==0xfe83fffc and polls[0]:value=0xffffffff
            elif 0xfe83a000<=address<=0xfe83bffc and image[0] is not None:
                value=struct.unpack_from('<I',image[0],address-0xfe83a000)[0]
                if wrong_image and address==0xfe83bffc:value^=1
            else:self.fail('unapproved device read '+hex(address))
            word(address,value)
        def write(u,access,address,size,value,data):
            if address>=0xfd000000:
                self.assertIn(address,(0xfe802040,0xfe8020d4,0xfe83fffc,0xfe830400));self.assertEqual(size,4)
                stores.append((address,value))
                if address==0xfe830400:self.assertEqual(value,original[address],'CPU wrote manufactured marker')
                if len(stores)==ignore_store:return
                registers[address]=value
                if address==0xfe83fffc and value==3:
                    self.assertEqual(registers[0xfe802040],physical)
                    self.assertEqual(registers[0xfe8020d4],5)
                    # Validate the actual produced512-entry table and full owned
                    # source layout, including unused entries and the guard page.
                    sg=struct.unpack('<1024I',u.mem_read(allocation,4096))
                    for index in range(512):
                        expected=physical+(index+1)*4096 if index<6 else physical+24576
                        self.assertEqual(sg[index*2:index*2+2],(expected,0))
                    image[0]=bytes(u.mem_read(allocation+4096,16384))
                    for offset in range(24,16384,4):
                        self.assertEqual(struct.unpack_from('<I',image[0],offset)[0],0x87)
            elif allocation and allocation<=address<allocation+28672:
                self.assertEqual(size,4)
            else:
                self.assertGreaterEqual(address,0x6000);self.assertLessEqual(address+size,0x8000)
        uc.hook_add(UC_HOOK_CODE,kernel);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x1800,count=5000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x1800,'unbounded payload')
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        return dict(result=uc.reg_read(UC_X86_REG_EAX),registers=registers,original=original,
                    stores=stores,reads=reads,calls=calls,polls=polls[0],image=image[0],counter_calls=counter_calls[0])

    def test_successful_owned_boot_and_exact_restoration(self):
        for delay in (1,2,17):
            result=self.execute(marker_after=delay,clear_x=True)
            self.assertEqual(result['result'],0xd1000000|delay)
            self.assertEqual(result['registers'],result['original'])
            self.assertEqual(result['stores'],[(0xfe802040,0x180000),(0xfe8020d4,5),(0xfe83fffc,3),
                                              (0xfe83fffc,0),(0xfe830400,0x123456),(0xfe8020d4,1544),
                                              (0xfe802040,0x399c000)])
            self.assertEqual([name for name,args in result['calls']],['frequency','allocate','physical'])

    def test_initial_context_mismatch_has_no_device_store(self):
        for address,value in ((0xfe83fffc,3),(0xfe801004,0xafb),(0xfe802000,15),
                              (0xfe801100,0x71f0f),(0xfe801000,1),(0xfd6806a0,0),
                              (0xfe802040,0),(0xfe802040,0x399c004),(0xfe8020d4,0xffffffff),
                              (0xfe830400,0x5a34c1),(0xfe830400,0xffffffff)):
            result=self.execute(context={address:value})
            self.assertIn(result['result'],(0xdf000001,0xdf000002))
            self.assertEqual(result['stores'],[]);self.assertEqual(result['calls'],[])

    def test_api_allocation_and_alias_fail_without_device_store(self):
        for options,expected in ((dict(malformed=True),3),(dict(frequency=3375001),3),
                                 (dict(allocation=0),4),(dict(physical=0),5),
                                 (dict(physical=0x180004),5),(dict(physical=0x3ffa000),5),
                                 (dict(allocation=0x90180000),5)):
            result=self.execute(**options)
            self.assertEqual(result['result'],0xdf000000|expected);self.assertEqual(result['stores'],[])

    def test_each_ignored_store_stops_without_recovery(self):
        expected={1:8,2:9,3:10,4:16,5:17,6:19,7:20}
        for index,stage in expected.items():
            result=self.execute(ignore_store=index)
            self.assertEqual(result['result'],0xdf000000|stage)
            self.assertEqual(len(result['stores']),index)

    def test_loaded_image_marker_or_fresh_controls_cannot_be_faked(self):
        for options,stage in ((dict(wrong_marker=True),11),(dict(wrong_image=True),15),
                              (dict(changed_sg=True),15),(dict(changed_reset=True),15)):
            result=self.execute(**options)
            self.assertEqual(result['result'],0xdf000000|stage)
            self.assertEqual(len(result['stores']),3)

    def test_time_poll_and_backward_clock_bounds_retain_owned_mapping(self):
        for options,stage in ((dict(clock_step=33750),13),(dict(clock_step=0),14),
                              (dict(clock_values=[100,99]),12)):
            result=self.execute(marker_after=None,**options)
            self.assertEqual(result['result'],0xdf000000|stage)
            self.assertEqual(len(result['stores']),3)
            self.assertEqual(result['registers'][0xfe802040],0x180000)
            self.assertEqual(result['registers'][0xfe83fffc],3)
            self.assertLessEqual(result['polls'],100000)

    def test_actual_generated_image_on_pinned_dsp_cpu(self):
        checker=os.environ.get('PROBE_DSP_BOOT_CHECK')
        if not checker:self.skipTest('set PROBE_DSP_BOOT_CHECK to built hardware-free DSP checker')
        result=self.execute()
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/'authored-boot.bin';image.write_bytes(result['image'])
            completed=subprocess.run([checker,str(image)],capture_output=True,text=True,timeout=10)
            self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
            self.assertIn('no peripheral access',completed.stdout)
            # A different write target must fail independently even when the
            # host's abstract marker publication model would have succeeded.
            corrupted=bytearray(result['image']);struct.pack_into('<I',corrupted,4,0xfd)
            image.write_bytes(corrupted)
            completed=subprocess.run([checker,str(image)],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(completed.returncode,0)

    def host(self,reply='RET d1000001',risk=True,identity='PONG xboxlle-probe v0.4.0'):
        calls=[]
        class Agent:
            def __init__(self,host,timeout):pass
            def request(self,command,**kwargs):
                calls.append((command,kwargs))
                if command=='PING':return identity
                if isinstance(reply,Exception):raise reply
                return reply
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'result'
            with patch.object(observer,'AgentClient',Agent),patch.object(observer,'compile_fixed',return_value=self.code),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                try:result=observer.run(argparse.Namespace(host='127.0.0.1',output=output,i_accept_the_risk=risk))
                except observer.ProbeError:result=3
            files={item.name:item.read_text() for item in output.glob('*')}
        return result,calls,files

    def test_host_exact_single_arm_path_and_result_fields(self):
        result,calls,files=self.host()
        self.assertEqual(result,0);self.assertEqual(len(calls),2)
        self.assertEqual(calls[1],('EXEC '+str(len(self.code)),dict(payload=self.code,dangerous=True)))
        summary=json.loads(files['summary.json'])
        self.assertEqual(summary['mmio_writes'],7);self.assertEqual(summary['retained_owned_scratch_bytes'],28672)

    def test_host_failures_never_retry_or_restore(self):
        self.assertEqual(self.host(risk=False)[:2],(3,[]))
        result,calls,_=self.host(identity='PONG xlle-agent v0.2')
        self.assertEqual(result,2);self.assertEqual(len(calls),1)
        for reply in ('RET df000014','RET d1000000','RET d10186a1','RET d1020001',
                      'RET 100000000','ERR denied',OSError('timeout')):
            result,calls,files=self.host(reply=reply)
            self.assertEqual(result,2);self.assertEqual(len(calls),2)
            self.assertNotIn('summary.json',files)
            self.assertEqual(json.loads(files['status.json'])['status'],'stopped_human_inspection_required')


if __name__=='__main__':unittest.main()
