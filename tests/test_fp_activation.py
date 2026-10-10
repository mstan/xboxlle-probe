"""Actual compiled crop payload with independent programmed/active banks."""
import argparse
from contextlib import redirect_stderr,redirect_stdout
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
import observe_fp_activation as observation
from payload_build import compile_fixed
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ESI,
                              UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_EDX,UC_X86_REG_ESP,UC_X86_REG_EIP)


class ActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code=compile_fixed('fp_activation');cls.wait_code=compile_fixed('fp_activation',wait_window=True)

    def execute(self,mode='request',ack_delays=(1,1),context=None,active_initial=0,
                ignore_selector=False,ignore_program=False,fail_restore=False,bad_av=None,
                corrupt_control=False,wait_window=False,frequency=3375000,clock_values=None,
                clock_step=16875,malformed_kernel=False):
        uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,self.wait_code if wait_window else self.code)
        uc.mem_map(0x7000,0x2000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
        uc.reg_write(UC_X86_REG_ESP,0x8000);uc.mem_map(0xfd680000,0x1000)
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items():uc.reg_write(reg,value)
        registers={0xfd680848:0x10100111,0xfd680824:935,0xfd680804:524}
        registers.update(context or {})
        prog=[0];active=[active_initial];phase=[1];requests=[];av_reads=[0];stores=[]
        ticks=[1<<40];clock_calls=[0];frequency_calls=[0];ack_origin=[0]
        if wait_window:
            uc.mem_map(0x80010000,0x40000)
            def word(address,value):uc.mem_write(address,struct.pack('<I',value))
            uc.mem_write(0x80010000,b'MZ' if not malformed_kernel else b'zz');word(0x8001003c,0x80)
            word(0x80010080,0x4550);uc.mem_write(0x80010098,struct.pack('<H',0x10b))
            word(0x800100d0,0x40000);word(0x800100f8,0x2000);word(0x800100fc,0x1000)
            word(0x80012010,1);word(0x80012014,400);word(0x8001201c,0x2400)
            word(0x80012400+125*4,0xa000);word(0x80012400+126*4,0xb000)
        def kernel(u,address,size,data):
            if address not in (0x8001a000,0x8001b000):return
            sp=u.reg_read(UC_X86_REG_ESP)
            if address==0x8001b000:
                frequency_calls[0]+=1;value=frequency
            else:
                index=clock_calls[0];clock_calls[0]+=1
                if clock_values is not None:value=clock_values[min(index,len(clock_values)-1)]
                else:ticks[0]+=clock_step;value=ticks[0]
                if mode=='deferred' and requests and value-ack_origin[0]>=168750:active[0]=prog[0]
            u.reg_write(UC_X86_REG_EAX,value&0xffffffff);u.reg_write(UC_X86_REG_EDX,value>>32)
            u.reg_write(UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(UC_X86_REG_ESP,sp+4)
        def read(u,access,address,size,value,data):
            if address<0xfd680000:return
            self.assertEqual(size,4)
            if address in registers:
                value=registers[address]
                if address==0xfd680848 and corrupt_control and stores:value=0xffffffff
            elif address==0xfd680834:
                value=prog[0] if registers[0xfd680848]&0x100000 else active[0]
            elif address==0xfd6806a0:
                if not requests:value=0x11
                else:
                    av_reads[0]+=1;target=requests[-1];delay=ack_delays[len(requests)-1]
                    if bad_av is not None:value=bad_av
                    elif delay is None or av_reads[0]<delay:value=target|((target^1)<<4)
                    else:
                        value=target|(target<<4);phase[0]=target
                        ack_origin[0]=ticks[0]
                        if mode=='request' and not (fail_restore and len(requests)==2):active[0]=prog[0]
            else:self.fail('unreviewed register read')
            u.mem_write(address,struct.pack('<I',value))
        def write(u,access,address,size,value,data):
            if address>=0xfd680000:
                self.assertEqual(size,4);self.assertIn(address,(0xfd680848,0xfd680834,0xfd6806a0))
                stores.append((address,value))
                if address==0xfd680848:
                    self.assertIn(value,(0x10100111,0x10000111))
                    if not ignore_selector:registers[address]=value
                elif address==0xfd680834:
                    self.assertIn(value,(0,1))
                    if not ignore_program:prog[0]=value
                    if mode=='immediate':active[0]=prog[0]
                else:
                    self.assertEqual(value,0 if not requests else 1)
                    self.assertLess(len(requests),2);requests.append(value);av_reads[0]=0
            else:
                self.assertGreaterEqual(address,0x7000);self.assertLess(address+size,0x8001)
        uc.hook_add(UC_HOOK_CODE,kernel);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x1800,count=60000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x1800)
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        return dict(result=uc.reg_read(UC_X86_REG_EAX),stores=stores,requests=requests,
                    programmed=prog[0],active=active[0],control=registers[0xfd680848],phase=phase[0],
                    clock_calls=clock_calls[0],frequency_calls=frequency_calls[0])

    def test_actual_wait_variant_observes_deferred_banks_and_restores(self):
        result=self.execute(wait_window=True,mode='deferred')
        self.assertEqual(result['result'],0xc1000052)
        self.assertEqual(result['clock_calls'],22);self.assertEqual(result['frequency_calls'],1)
        self.assertEqual((result['programmed'],result['active'],result['control'],result['phase']),
                         (0,0,0x10100111,1))
        self.assertEqual(len(result['stores']),12)

    def test_wait_preconditions_and_backward_clock_cannot_qualify(self):
        for kwargs in (dict(frequency=0),dict(frequency=3375001),dict(malformed_kernel=True)):
            result=self.execute(wait_window=True,**kwargs)
            self.assertEqual(result['result'],0xcf00000a);self.assertEqual(result['stores'],[])
        result=self.execute(wait_window=True,clock_values=[100,99])
        self.assertEqual(result['result'],0xcf00000b);self.assertEqual(result['requests'],[0])

    def test_stopped_clock_has_finite_call_budget(self):
        result=self.execute(wait_window=True,clock_values=[100])
        self.assertEqual(result['result'],0xcf00000c)
        self.assertEqual(result['clock_calls'],2000001);self.assertEqual(result['requests'],[0])

    def test_actual_independent_bank_models_and_restoration(self):
        for mode,flags in (('request',18),('immediate',19),('unchanged',16)):
            result=self.execute(mode=mode)
            self.assertEqual(result['result'],0xc1000000|(2<<5)|flags)
            self.assertEqual(len(result['stores']),12);self.assertEqual(result['requests'],[0,1])
            self.assertEqual((result['programmed'],result['active'],result['control'],result['phase']),
                             (0,0,0x10100111,1))
            self.assertEqual([v for a,v in result['stores'] if a==0xfd680834],[1,0])

    def test_pending_and_final_permitted_polls(self):
        for delays in ((2,2),(17,3),(100000,100000)):
            result=self.execute(ack_delays=delays)
            self.assertEqual(result['result'],0xc1000000|(sum(delays)<<5)|30)
            self.assertEqual(len(result['stores']),12)

    def test_initial_context_and_active_bank_fail_before_crop(self):
        for context in ({0xfd680848:0x10000111},{0xfd680824:775},{0xfd680804:525}):
            result=self.execute(context=context)
            self.assertEqual(result['result'],0xcf000001);self.assertEqual(result['stores'],[])
        result=self.execute(active_initial=1)
        self.assertEqual(result['result'],0xcf000002)
        self.assertEqual(len(result['stores']),2);self.assertEqual(result['requests'],[])

    def test_bad_selector_or_program_never_sends_av(self):
        for kwargs in (dict(ignore_selector=True),dict(corrupt_control=True)):
            result=self.execute(**kwargs)
            self.assertEqual(result['result'],0xcf000002);self.assertEqual(result['requests'],[])
            self.assertEqual(len(result['stores']),1)
        result=self.execute(ignore_program=True)
        self.assertEqual(result['result'],0xcf000003);self.assertEqual(result['requests'],[])

    def test_failed_av_has_no_second_transaction_or_retry(self):
        for kwargs in (dict(ack_delays=(None,1)),dict(bad_av=0xffffffff)):
            result=self.execute(**kwargs)
            self.assertEqual(result['result'],0xcf000005);self.assertEqual(result['requests'],[0])
            self.assertEqual(result['programmed'],1)

    def test_failed_restore_cannot_return_success(self):
        result=self.execute(fail_restore=True)
        self.assertEqual(result['result'],0xcf000009);self.assertEqual(result['requests'],[0,1])
        self.assertEqual(result['programmed'],0);self.assertEqual(result['active'],1)

    def host(self,reply='RET c1000052',risk=True,identity='PONG xboxlle-probe v0.4.0',existing=False,wait_window=False):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'session';calls=[]
            if existing:output.mkdir()
            class Agent:
                def __init__(self,host,timeout):pass
                def request(self,command,**kwargs):
                    calls.append((command,kwargs))
                    if command=='PING':return identity
                    if isinstance(reply,Exception):raise reply
                    return reply
            with patch.object(observation,'compile_fixed',return_value=self.code),patch.object(observation,'AgentClient',Agent),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                try:result=observation.run(argparse.Namespace(host='127.0.0.1',output=output,i_accept_the_risk=risk,wait_window=wait_window))
                except(OSError,observation.ProbeError):result=3
            return result,calls,{p.name:p.read_text() for p in output.glob('*')}

    def test_host_fixed_arm_path_and_real_fields(self):
        result,calls,files=self.host();self.assertEqual(result,0);self.assertEqual(len(calls),2)
        self.assertEqual(calls[1],('EXEC '+str(len(self.code)),dict(payload=self.code,dangerous=True)))
        summary=json.loads(files['summary.json'])
        self.assertEqual((summary['active_start_before_request'],summary['active_start_after_ack']), (0,1))
        self.assertEqual(summary['mmio_writes'],12);self.assertEqual(summary['total_postwrite_av_reads'],2)
        result,calls,files=self.host(wait_window=True)
        self.assertEqual(result,0)
        self.assertEqual(json.loads(files['summary.json'])['minimum_post_ack_wait_ms'],50)

    def test_host_failure_never_retries_or_overwrites(self):
        for kwargs in (dict(risk=False),dict(existing=True)):
            result,calls,_=self.host(**kwargs);self.assertEqual(result,3);self.assertEqual(calls,[])
        result,calls,_=self.host(identity='PONG xlle-agent v0.2');self.assertEqual(result,2);self.assertEqual(len(calls),1)
        for bad in ('RET cf000009','RET c1000042','RET c1000032','RET c1800052',
                    'RET c1000000','RET c161a832','RET 100000000','ERR denied',OSError('timeout')):
            result,calls,files=self.host(reply=bad)
            self.assertEqual(result,2);self.assertEqual(len(calls),2);self.assertNotIn('summary.json',files)
            if isinstance(bad,str):self.assertIn(bad,files['reply.txt'])


if __name__=='__main__':unittest.main()
