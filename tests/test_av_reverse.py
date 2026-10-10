"""Hardware-free proof of actual reverse payload and fail-closed host."""
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
import observe_av_reverse as reverse
from payload_build import compile_fixed
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ESI,
                              UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)


class ReverseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.code=compile_fixed('av_reverse')

    def execute(self,initial=(0,0),ack_after=1,bad_post=None,context=None):
        uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,self.code)
        uc.mem_map(0x7000,0x2000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
        uc.reg_write(UC_X86_REG_ESP,0x8000);uc.mem_map(0xfd680000,0x1000)
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items():uc.reg_write(reg,value)
        registers={0xfd680848:0x10100111,0xfd680824:935,0xfd680804:524,0xfd680834:0}
        registers.update(context or {});writes=[];reads=[];pre=[0];post=[0]
        def read(u,access,address,size,value,data):
            if address<0xfd680000:return
            self.assertEqual(size,4);reads.append(address)
            if address in registers:value=registers[address]
            elif address==0xfd6806a0:
                if not writes:
                    value=initial[min(pre[0],len(initial)-1)];pre[0]+=1
                else:
                    post[0]+=1
                    value=bad_post if bad_post is not None else (0x11 if ack_after is not None and post[0]>=ack_after else 1)
            else:self.fail('unreviewed register read')
            u.mem_write(address,struct.pack('<I',value))
        def write(u,access,address,size,value,data):
            if address>=0xfd680000:
                self.assertEqual((address,size,value),(0xfd6806a0,4,1));writes.append((address,value))
            else:
                self.assertGreaterEqual(address,0x7000);self.assertLess(address+size,0x8001)
        uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x1800,count=2000000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x1800)
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        return uc.reg_read(UC_X86_REG_EAX),writes,pre[0],post[0]

    def test_actual_immediate_and_pending_ack(self):
        for delay in (1,2,17,100000):
            result,writes,pre,post=self.execute(ack_after=delay)
            self.assertEqual(result,0xe1000000|((3 if delay==1 else 1)<<17)|delay)
            self.assertEqual(len(writes),1);self.assertEqual((pre,post),(2,delay))

    def test_preconditions_never_write(self):
        for initial in ((0x11,0x11),(0,0x11),(1,1),(0xffffffff,0xffffffff)):
            result,writes,pre,post=self.execute(initial=initial)
            self.assertEqual(result,0xe4000001);self.assertEqual(writes,[]);self.assertEqual(post,0)
        for address,value in ((0xfd680848,0x10000111),(0xfd680824,775),(0xfd680804,1),(0xfd680834,1)):
            result,writes,pre,post=self.execute(context={address:value})
            self.assertEqual(result,0xe4000000);self.assertEqual(writes,[]);self.assertEqual(pre,0)

    def test_bad_observation_and_timeout_never_retry_or_restore(self):
        for value in (0,0x10,0x12,0xffffffff):
            result,writes,pre,post=self.execute(bad_post=value)
            self.assertEqual(result>>24,0xe3);self.assertEqual(len(writes),1);self.assertEqual(post,1)
        result,writes,pre,post=self.execute(ack_after=None)
        self.assertEqual(result,0xe2000000|(1<<17)|100000)
        self.assertEqual(len(writes),1);self.assertEqual(post,100000)

    def host(self,reply='RET e1060001',risk=True,identity='PONG xboxlle-probe v0.4.0',existing=False):
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
            with patch.object(reverse,'compile_fixed',return_value=self.code),patch.object(reverse,'AgentClient',Agent),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                try:result=reverse.run(argparse.Namespace(host='127.0.0.1',output=output,i_accept_the_risk=risk))
                except (OSError,reverse.ProbeError):result=3
            return result,calls,{p.name:p.read_text() for p in output.glob('*')}

    def test_host_armed_once_and_correct_decoding(self):
        for reply,first,polls in (('RET e1060001',0x11,1),('RET e1020011',1,17)):
            result,calls,files=self.host(reply=reply)
            self.assertEqual(result,0);self.assertEqual(len(calls),2)
            self.assertEqual(calls[1],('EXEC '+str(len(self.code)),dict(payload=self.code,dangerous=True)))
            summary=json.loads(files['summary.json'])
            self.assertEqual((summary['first_postwrite'],summary['postwrite_reads']),(first,polls))
            self.assertEqual(summary['mmio_writes'],1);self.assertFalse(summary['restoring_request'])

    def test_host_refusals_and_failures_stop(self):
        for kwargs in (dict(risk=False),dict(existing=True)):
            result,calls,files=self.host(**kwargs);self.assertEqual(result,3);self.assertEqual(calls,[])
        result,calls,_=self.host(identity='PONG xlle-agent v0.2');self.assertEqual(result,2);self.assertEqual(len(calls),1)
        for bad in ('RET e4000001','RET e2060001','RET e1060000','RET e10786a1','RET e10e0001',
                    'RET e1040001','RET 100000000','ERR denied',OSError('timeout')):
            result,calls,files=self.host(reply=bad)
            self.assertEqual(result,2);self.assertEqual(len(calls),2);self.assertNotIn('summary.json',files)
            if isinstance(bad,str):self.assertIn(bad,files['reply.txt'])

    def test_closed_builder_rejects_other_inputs(self):
        for name,held in (('other',False),('av_reverse',True),('fe_fence',1)):
            with self.assertRaises(reverse.ProbeError):compile_fixed(name,held)


if __name__=='__main__':unittest.main()
