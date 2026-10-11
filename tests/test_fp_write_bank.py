"""Actual compiled x86, independent bank models and terminal host failures."""
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
import observe_fp_write_bank as host
from payload_build import compile_fixed
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ESI,
                              UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)

class WriteBank(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.code=compile_fixed('fp_write_bank')
    def execute(self,model='program',phase=0x11,bad_at=None):
        uc=Uc(UC_ARCH_X86,UC_MODE_32);uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,self.code)
        uc.mem_map(0x7000,0x2000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
        uc.reg_write(UC_X86_REG_ESP,0x8000);uc.mem_map(0xfd680000,0x1000)
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,v in saved.items():uc.reg_write(reg,v)
        control=[0x10100111];banks=[0,0];operations=[];reads=[0]
        def read(u,access,address,size,value,data):
            if address<0xfd680000:return
            self.assertEqual(size,4)
            if address==0xfd680848:value=control[0]
            elif address==0xfd680834:value=banks[1 if control[0]&0x100000 else 0]
            elif address==0xfd680824:value=935
            elif address==0xfd680804:value=524
            elif address==0xfd6806a0:value=phase
            else:self.fail('unreviewed register read')
            reads[0]+=1
            if reads[0]==bad_at:value=0xffffffff
            operations.append(('R',address,value));u.mem_write(address,struct.pack('<I',value))
        def write(u,access,address,size,value,data):
            if address<0xfd680000:
                self.assertGreaterEqual(address,0x7000);self.assertLessEqual(address+size,0x8000);return
            self.assertEqual(size,4);operations.append(('W',address,value))
            if address==0xfd680848:
                self.assertIn(value,(0x10000111,0x10100111));control[0]=value
            elif address==0xfd680834:
                self.assertIn(value,(0,1))
                if model=='selected':banks[1 if control[0]&0x100000 else 0]=value
                elif model=='program':banks[1]=value
                elif model=='broadcast':banks[:]=[value,value]
                elif model=='ignored':pass
                else:self.fail('bad model')
            else:self.fail('unreviewed register store')
        uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x1800,count=50000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x1800)
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,v in saved.items():self.assertEqual(uc.reg_read(reg),v)
        return uc.reg_read(UC_X86_REG_EAX),operations,control[0],banks
    def test_four_independent_write_policies_and_two_phases(self):
        expected={'program':2,'selected':5,'broadcast':3,'ignored':0}
        sequence=[(0xfd680848,0x10000111),(0xfd680834,1),(0xfd680848,0x10100111),
                  (0xfd680834,0),(0xfd680848,0x10000111),(0xfd680834,0),(0xfd680848,0x10100111)]
        for model,flags in expected.items():
            for phase in (0,0x11):
                result,ops,control,banks=self.execute(model,phase)
                self.assertEqual(result,0xc2000080|flags|(8 if phase else 0))
                self.assertEqual([(a,v) for op,a,v in ops if op=='W'],sequence)
                self.assertEqual((control,banks),(0x10100111,[0,0]))
    def test_every_unexpected_read_stops_before_another_hardware_operation(self):
        for model in ('program','selected','broadcast','ignored'):
            _,baseline,_,_=self.execute(model);total=sum(op=='R' for op,_,_ in baseline)
            for position in range(1,total+1):
                result,ops,_,_=self.execute(model,bad_at=position)
                self.assertEqual(result&0xfffffff0,0xcf200000)
                self.assertEqual(ops[-1][0::2],('R',0xffffffff))
                self.assertEqual(sum(op=='R' for op,_,_ in ops),position)
                before_bad=[];count=0
                for item in baseline:
                    if item[0]=='R':count+=1
                    if count==position:break
                    before_bad.append(item)
                self.assertEqual([x for x in ops if x[0]=='W'],[x for x in before_bad if x[0]=='W'])
    def test_payload_has_no_calls_ports_interrupt_changes_or_other_absolute_writes(self):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        dis=Cs(CS_ARCH_X86,CS_MODE_32)
        for ins in dis.disasm(self.code,0):
            self.assertNotIn(ins.mnemonic,('call','in','out','int','cli','sti','hlt'))
        for name in ('unknown','fp_write_bank;gp_boot'):
            with self.assertRaises(host.ProbeError):compile_fixed(name)
        with self.assertRaises(host.ProbeError):compile_fixed('fp_write_bank',wait_window=True)
    def host(self,reply='RET c200008a',risk=True,identity='PONG xboxlle-probe v0.4.0'):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'session';calls=[]
            class Agent:
                def __init__(self,*args,**kwargs):pass
                def request(self,command,**kwargs):
                    calls.append((command,kwargs))
                    if command=='PING':return identity
                    if isinstance(reply,Exception):raise reply
                    return reply
            with patch.object(host,'compile_fixed',return_value=self.code),patch.object(host,'AgentClient',Agent),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                try:result=host.run(argparse.Namespace(host='127.0.0.1',output=out,i_accept_the_risk=risk))
                except (OSError,host.ProbeError):result=3
            return result,calls,{p.name:p.read_text() for p in out.glob('*')}
    def test_host_decodes_only_success_and_sends_one_armed_exec(self):
        for flags in range(16):
            result,calls,files=self.host(reply=f'RET {0xc2000080|flags:08x}')
            self.assertEqual(result,0);self.assertEqual(len(calls),2)
            self.assertEqual(calls[1],('EXEC '+str(len(self.code)),dict(payload=self.code,dangerous=True)))
            q=json.loads(files['summary.json']);self.assertEqual(q['mmio_writes'],7)
            self.assertEqual(q['selected_after_write'],flags&1)
            self.assertEqual(q['programmed_after_write'],(flags>>1)&1)
            self.assertEqual(q['selected_after_program_restore'],(flags>>2)&1)
    def test_host_error_identity_and_missing_risk_never_retry(self):
        result,calls,_=self.host(risk=False);self.assertEqual(result,3);self.assertEqual(calls,[])
        result,calls,_=self.host(identity='PONG old');self.assertEqual(result,2);self.assertEqual(len(calls),1)
        for reply in ('RET cf200003','RET c2000090','RET c2000000','malformed',OSError('timeout')):
            result,calls,files=self.host(reply=reply);self.assertEqual(result,2);self.assertEqual(len(calls),2)
            self.assertNotIn('summary.json',files);self.assertEqual(json.loads(files['status.json'])['status'],'stopped_no_retry')

if __name__=='__main__':unittest.main()
