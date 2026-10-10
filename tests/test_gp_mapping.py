"""Execute fixed query bytes; candidate RAM and device stores are forbidden."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'host'))
import read_gp_mapping as observer
from payload_build import compile_fixed
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP


class MappingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.code=compile_fixed('gp_mapping')

    def execute(self,mapped=15,matching=15,calibration=(1,0),kernel_physical=0x10000,
                nonboolean=False,sg=0x399c000,maximum=1544,reset=0,av=0x11,
                changed=False,malformed=False):
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        uc.mem_map(0x1000,0x1000);uc.mem_write(0x1000,self.code)
        uc.mem_map(0x6000,0x3000);uc.mem_write(0x8000,struct.pack('<I',0x1800))
        uc.reg_write(UC_X86_REG_ESP,0x8000)
        uc.mem_map(0x80010000,0x40000);uc.mem_map(0xfd680000,0x1000)
        uc.mem_map(0xfe802000,0x1000);uc.mem_map(0xfe83f000,0x1000)
        def word(address,value):uc.mem_write(address,struct.pack('<I',value))
        uc.mem_write(0x80010000,b'zz' if malformed else b'MZ');word(0x8001003c,0x80)
        word(0x80010080,0x4550);uc.mem_write(0x80010098,struct.pack('<H',0x10b))
        word(0x800100d0,0x40000);word(0x800100f8,0x2000);word(0x800100fc,0x1000)
        word(0x80012010,1);word(0x80012014,400);word(0x8001201c,0x2400)
        word(0x80012400+(174-1)*4,0xa000);word(0x80012400+(173-1)*4,0xb000)
        registers={0xfe83fffc:reset,0xfd6806a0:av,0xfe802040:sg,0xfe8020d4:maximum}
        calls=[];reads=[];stores=[];seen={}
        saved={UC_X86_REG_EBX:0x12345678,UC_X86_REG_ESI:0x23456789,
               UC_X86_REG_EDI:0x34567890,UC_X86_REG_EBP:0x4567890a}
        for reg,value in saved.items():uc.reg_write(reg,value)
        def kernel(u,address,size,data):
            if address not in (0x8001a000,0x8001b000):return
            sp=u.reg_read(UC_X86_REG_ESP);arg=struct.unpack('<I',u.mem_read(sp+4,4))[0]
            name='valid' if address==0x8001a000 else 'physical';calls.append((name,arg))
            if name=='valid':
                if arg==0x80010000:value=calibration[0]
                elif arg==0x40000000:value=calibration[1]
                else:
                    index=(arg-(0x80000000|sg))//4096
                    self.assertIn(index,range(4));self.assertEqual(arg,(0x80000000|sg)+index*4096)
                    value=17 if nonboolean else int(bool(mapped&(1<<index)))
                value|=0xaabbcc00 # BOOLEAN uses AL; upper EAX is unspecified.
            elif arg==0x80010000:value=kernel_physical
            else:
                index=(arg-(0x80000000|sg))//4096
                self.assertTrue(mapped&(1<<index),'physical query on invalid page')
                value=sg+index*4096+(0 if matching&(1<<index) else 4096)
            u.reg_write(UC_X86_REG_EAX,value)
            u.reg_write(UC_X86_REG_EIP,struct.unpack('<I',u.mem_read(sp,4))[0]);u.reg_write(UC_X86_REG_ESP,sp+8)
        def read(u,access,address,size,value,data):
            if 0x80010000<=address<0x80050000:
                self.assertLessEqual(address+size,0x80050000);return
            if address>=0x80000000:
                self.assertIn(address,registers,'candidate RAM was dereferenced')
                self.assertEqual(size,4);reads.append(address);seen[address]=seen.get(address,0)+1
                word(address,registers[address]^(1 if changed and seen[address]>1 else 0));return
            self.assertGreaterEqual(address,0x1000);self.assertLess(address,0x9000)
        def write(u,access,address,size,value,data):
            stores.append((address,size))
            self.assertGreaterEqual(address,0x6000,'write outside stack')
            self.assertLessEqual(address+size,0x8000,'candidate/device/kernel write')
        uc.hook_add(UC_HOOK_CODE,kernel);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
        uc.emu_start(0x1000,0x1800,count=100000)
        self.assertEqual(uc.reg_read(UC_X86_REG_EIP),0x1800)
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP),0x8004)
        for reg,value in saved.items():self.assertEqual(uc.reg_read(reg),value)
        return uc.reg_read(UC_X86_REG_EAX),calls,reads,stores

    def test_all_four_pages_and_physical_matches_without_candidate_load(self):
        result,calls,reads,stores=self.execute()
        self.assertEqual(result,0xd20000ff);self.assertEqual(len(reads),8)
        self.assertEqual([v for n,v in calls if n=='physical'],[0x80010000,0x8399c000,0x8399d000,0x8399e000,0x8399f000])

    def test_unmapped_pages_never_call_physical_or_load_ram(self):
        for mapped in (0,1,5,10,14):
            with self.subTest(mapped=mapped):
                result,calls,_,_=self.execute(mapped=mapped,matching=mapped)
                self.assertEqual(result,0xd2000000|mapped|(mapped<<4))
                self.assertEqual(len([c for c in calls if c[0]=='physical']),1+mapped.bit_count())

    def test_mapped_does_not_assert_expected_physical_alias(self):
        self.assertEqual(self.execute(matching=5)[0],0xd200005f)

    def test_boolean_calibration_cannot_reverse_interpretation(self):
        for calibration in ((0,1),(0,0),(1,1),(17,0)):
            with self.subTest(calibration=calibration):
                result,calls,reads,_=self.execute(calibration=calibration)
                self.assertEqual(result,0xde000002);self.assertFalse(reads)
                self.assertFalse(any(n=='physical' for n,v in calls))

    def test_kernel_physical_calibration_precedes_candidate_queries(self):
        result,calls,reads,_=self.execute(kernel_physical=0x11000)
        self.assertEqual(result,0xde000003);self.assertFalse(reads);self.assertEqual(len(calls),3)

    def test_fixed_context_and_range_guards(self):
        for options in (dict(reset=3),dict(av=0),dict(maximum=1543),dict(sg=0),dict(sg=1),dict(sg=0x4000000)):
            with self.subTest(options=options):
                result,calls,_,_=self.execute(**options)
                self.assertEqual(result,0xde000004);self.assertEqual(len(calls),3)

    def test_nonboolean_query_stops_without_physical_followup(self):
        result,calls,_,_=self.execute(nonboolean=True)
        self.assertEqual(result,0xde000005);self.assertEqual(len(calls),4)

    def test_changed_context_is_reported_without_recovery_store(self):
        self.assertEqual(self.execute(changed=True)[0],0xde000006)

    def test_malformed_exports_stop_before_api_or_device_reads(self):
        result,calls,reads,_=self.execute(malformed=True)
        self.assertEqual(result,0xde000001);self.assertFalse(calls);self.assertFalse(reads)

    def host_run(self,reply='RET d20000ff',ping='PONG xboxlle-probe v0.4.0',fault=False):
        calls=[]
        class FakeAgent:
            def __init__(self,*args,**kwargs):pass
            def request(self,command,**kwargs):
                calls.append((command,kwargs))
                if command=='PING':return ping
                if fault:raise TimeoutError('authored timeout')
                return reply
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'private'
            args=SimpleNamespace(host='authored-loopback-only',output=output,i_accept_the_risk=True)
            with patch.object(observer,'AgentClient',FakeAgent),patch.object(observer,'compile_fixed',return_value=self.code),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                code=observer.run(args)
            return code,calls,json.loads((output/'status.json').read_text())

    def test_host_records_mapping_limits_and_exact_one_exec(self):
        code,calls,status=self.host_run()
        self.assertEqual(code,0);self.assertEqual(len(calls),2)
        self.assertEqual(calls[1][1],dict(payload=self.code,dangerous=True))
        self.assertTrue(status['mapping_is_not_allocation_ownership'])
        self.assertEqual(status['candidate_ram_loads_requested'],0);self.assertEqual(status['device_stores_requested'],0)

    def test_host_identity_failure_stops_before_arm_exec(self):
        code,calls,status=self.host_run(ping='old-agent')
        self.assertEqual(code,2);self.assertEqual(len(calls),1);self.assertEqual(status['exec_requests_may_have_been_sent'],0)

    def test_host_guard_and_malformed_results_do_not_retry(self):
        for reply in ('RET de000002','RET d20000f0','RET d2000100','malformed'):
            with self.subTest(reply=reply):
                code,calls,status=self.host_run(reply=reply)
                self.assertEqual(code,2);self.assertEqual(len(calls),2);self.assertFalse(status['automatic_retry'])

    def test_host_timeout_does_not_retry(self):
        code,calls,status=self.host_run(fault=True)
        self.assertEqual(code,2);self.assertEqual(len(calls),2);self.assertEqual(status['status'],'stopped')


if __name__=='__main__':unittest.main()
