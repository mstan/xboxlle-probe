"""Execute every exact payload offline and exercise bounded host stop paths."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import io,json,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'host'))
import read_rtc_context as rtc
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_INSN,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *


class RtcContextTests(unittest.TestCase):
    def test_exact_payload_preserves_cpu_and_only_selects_then_reads_aliases(self):
        for index, expected in rtc.SELECTORS:
            for flags in (0x247,0x47):
                with self.subTest(index=index,flags=flags):
                    uc=Uc(UC_ARCH_X86,UC_MODE_32)
                    uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,rtc.payload(index))
                    uc.mem_map(0x7000,0x2000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
                    uc.reg_write(UC_X86_REG_ESP,0x8000)
                    saved={UC_X86_REG_EBX:0x11111111,UC_X86_REG_ECX:0x33333333,
                           UC_X86_REG_EDX:0x55555555,UC_X86_REG_ESI:0x77777777,
                           UC_X86_REG_EDI:0x99999999,UC_X86_REG_EBP:0xaaaaaaaa,
                           UC_X86_REG_EFLAGS:flags}
                    for reg,value in saved.items():uc.reg_write(reg,value)
                    events=[];writes=[]
                    def outgoing(u,port,size,value,data):
                        self.assertEqual(u.reg_read(UC_X86_REG_EFLAGS)&0x200,0)
                        events.append(('out',port,size,value))
                    def incoming(u,port,size,data):
                        self.assertEqual(u.reg_read(UC_X86_REG_EFLAGS)&0x200,0)
                        events.append(('in',port,size));return expected
                    uc.hook_add(UC_HOOK_INSN,outgoing,None,1,0,UC_X86_INS_OUT)
                    uc.hook_add(UC_HOOK_INSN,incoming,None,1,0,UC_X86_INS_IN)
                    uc.hook_add(UC_HOOK_MEM_WRITE,lambda u,a,p,s,v,d:writes.append((p,s)))
                    uc.emu_start(0x1000,0x1800,count=32)
                    self.assertEqual(events,[('out',0x72,1,index),('in',0x71,1),('in',0x73,1)])
                    self.assertEqual(writes,[(0x7ffc,4),(0x7ff8,4),(0x7ff4,4)])
                    self.assertEqual(uc.reg_read(UC_X86_REG_EAX),expected<<8|expected)
                    self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
                    for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)

    def host(self,replacement=None,risk=True,existing=False):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'session'
            if existing:output.mkdir()
            replies=['PONG xboxlle-probe v0.4.0','RET 5555','RET 5555','RET aaaa','RET aaaa']
            if replacement:
                position,value=replacement;replies[position]=value
            calls=[]
            class Agent:
                def __init__(self,*args,**kwargs):pass
                def request(self,command,**kwargs):
                    calls.append((command,kwargs));result=replies[len(calls)-1]
                    if isinstance(result,Exception):raise result
                    return result
            with patch.object(rtc,'AgentClient',Agent),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                try:code=rtc.run(argparse.Namespace(host='mock',output=output,i_accept_the_risk=risk))
                except (OSError,rtc.ProbeError):code=3
            files={p.name:p.read_text() for p in output.glob('*')} if output.exists() else {}
            return code,calls,files

    def test_host_success_has_exact_operations_and_scope(self):
        code,calls,files=self.host();self.assertEqual(code,0);self.assertEqual(len(calls),5)
        for call,(index,expected) in zip(calls[1:],rtc.SELECTORS):
            payload=rtc.payload(index)
            self.assertEqual(call,('EXEC '+str(len(payload)),dict(payload=payload,dangerous=True)))
        summary=json.loads(files['summary.json'])
        self.assertEqual((summary['selector_writes'],summary['data_reads'],summary['cmos_data_writes']),(4,8,0))

    def test_preflight_rejects_without_connecting(self):
        for kwargs in (dict(risk=False),dict(existing=True)):
            code,calls,files=self.host(**kwargs);self.assertEqual(code,3);self.assertEqual(calls,[])
        for index in (-1,0,0x11,0x100,True):
            with self.assertRaises(rtc.ProbeError):rtc.payload(index)

    def test_wrong_identity_stops_before_exec(self):
        code,calls,files=self.host((0,'PONG xlle-agent v0.2'))
        self.assertEqual(code,2);self.assertEqual(len(calls),1)

    def test_unexpected_or_timeout_stops_without_further_write(self):
        for position in range(1,5):
            for bad in ('RET ff','RET 5556','RET ffffffff','RET 100000000','ERR denied',OSError('timeout')):
                code,calls,files=self.host((position,bad))
                self.assertEqual(code,2);self.assertEqual(len(calls),position+1)
                self.assertNotIn('summary.json',files)
                status=json.loads(files['status.json'])
                self.assertEqual(status['status'],'stopped_human_inspection_required')
                self.assertEqual(status['selector_writes_may_have_been_sent'],position)
                self.assertEqual(status['cmos_data_writes'],0)


if __name__=='__main__':unittest.main()
