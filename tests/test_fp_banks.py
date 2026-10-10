"""Actual fixed x86: selector-only stores, bounded reads and all abort paths."""
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

sys.path.insert(0, str(Path(__file__).parents[1] / 'host'))
import observe_fp_banks as banks
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                              UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                              UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EFLAGS)


class BankTests(unittest.TestCase):
    def execute(self, initial=0x10100111, htotal=935, vtotal=524, ignore_clear=False,
                ignore_restore=False, fresh_control=None):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x1000, 0x1000); uc.mem_write(0x1000, banks.payload())
        uc.mem_map(0x7000, 0x2000); uc.mem_write(0x8000, struct.pack('<I', 0x1800))
        uc.mem_map(0xfd680000, 0x1000)
        uc.reg_write(UC_X86_REG_ESP, 0x8000)
        registers = {UC_X86_REG_EBX: 0x12345678, UC_X86_REG_ECX: 0xaaaabbbb,
                     UC_X86_REG_EDX: 0xccccdddd, UC_X86_REG_ESI: 0x87654321,
                     UC_X86_REG_EDI: 0x34567890, UC_X86_REG_EBP: 0x4567890a,
                     UC_X86_REG_EFLAGS: 0x247}
        for reg, value in registers.items(): uc.reg_write(reg, value)
        control = [initial]; stores = []; reads = []; control_reads = [0]
        def read(u, access, address, size, value, data):
            if address < 0xfd680000: return
            self.assertEqual(size, 4); reads.append(address)
            if address == 0xfd680848:
                control_reads[0] += 1
                if control_reads[0] == 3 and fresh_control is not None: control[0] = fresh_control
                value = control[0]
            elif address == 0xfd680824: value = htotal
            elif address == 0xfd680804: value = vtotal
            else: self.fail('unapproved MMIO read')
            u.mem_write(address, struct.pack('<I', value))
        def write(u, access, address, size, value, data):
            if address < 0xfd680000:
                self.assertGreaterEqual(address, 0x7ff4); self.assertLess(address, 0x8000)
                return
            self.assertEqual(address, 0xfd680848); self.assertEqual(size, 4)
            stores.append(value)
            if (len(stores) == 1 and ignore_clear) or (len(stores) == 2 and ignore_restore): return
            control[0] = value
        uc.hook_add(UC_HOOK_MEM_READ, read); uc.hook_add(UC_HOOK_MEM_WRITE, write)
        uc.emu_start(0x1000, 0x1800, count=100)
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP), 0x8004)
        for reg, value in registers.items(): self.assertEqual(uc.reg_read(reg), value)
        return uc.reg_read(UC_X86_REG_EAX), control[0], stores, reads

    def test_actual_payload_and_restoration_for_distinct_banks(self):
        result, control, stores, reads = self.execute(htotal=775, vtotal=524)
        self.assertEqual(result, 0xab000000 | (524 << 12) | 775)
        self.assertEqual(control, 0x10100111)
        self.assertEqual(stores, [0x10000111, 0x10100111])
        self.assertEqual(reads, [0xfd680848, 0xfd680848, 0xfd680824, 0xfd680804, 0xfd680848, 0xfd680848])

    def test_unexpected_preconditions_have_no_store(self):
        for value in (0, 0xffffffff, 0x10000111, 0x10100110):
            result, control, stores, reads = self.execute(initial=value)
            self.assertEqual(result, 0xffffffff); self.assertEqual(stores, [])
            self.assertEqual(control, value); self.assertEqual(reads, [0xfd680848])

    def test_timing_failures_still_restore_selector(self):
        for kwargs in (dict(htotal=4096), dict(vtotal=0xffffffff), dict(htotal=0xffffffff)):
            result, control, stores, reads = self.execute(**kwargs)
            self.assertEqual(result, 0xffffffff); self.assertEqual(control, 0x10100111)
            self.assertEqual(stores, [0x10000111, 0x10100111])

    def test_selector_failure_skips_bank_and_reports_error(self):
        result, control, stores, reads = self.execute(ignore_clear=True)
        self.assertEqual(result, 0xffffffff); self.assertEqual(control, 0x10100111)
        self.assertNotIn(0xfd680824, reads); self.assertNotIn(0xfd680804, reads)
        self.assertEqual(len(stores), 1)

    def test_changed_fresh_word_is_never_written_back(self):
        for value in (0, 0xffffffff, 0x10000119, 0x10100111):
            result, control, stores, reads = self.execute(fresh_control=value)
            self.assertEqual(result, 0xffffffff); self.assertEqual(control, value)
            self.assertEqual(stores, [0x10000111])

    def test_failed_restore_cannot_return_success(self):
        result, control, stores, reads = self.execute(ignore_restore=True)
        self.assertEqual(result, 0xffffffff); self.assertEqual(control, 0x10000111)
        self.assertEqual(len(stores), 2)

    def test_zero_and_maximum_fields_encode_without_overlap(self):
        for h, v in ((0, 0), (4095, 4095), (0, 4095), (4095, 0)):
            result, _, _, _ = self.execute(htotal=h, vtotal=v)
            self.assertEqual(result, 0xab000000 | h | (v << 12))

    def host(self, reply='RET ab20c3a7', risk=True, identity='PONG xboxlle-probe v0.4.0'):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'observation'; calls = []
            class Agent:
                def __init__(self, host, timeout): pass
                def request(self, command, **kwargs):
                    calls.append((command, kwargs))
                    if command == 'PING': return identity
                    if isinstance(reply, Exception): raise reply
                    return reply
            with patch.object(banks, 'AgentClient', Agent), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try: result = banks.run(argparse.Namespace(host='127.0.0.1', output=output, i_accept_the_risk=risk))
                except banks.ProbeError: result = 3
            files = {p.name: p.read_text() for p in output.glob('*')}
            return result, calls, files

    def test_host_single_armed_payload_and_result(self):
        result, calls, files = self.host()
        self.assertEqual(result, 0); self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], ('EXEC ' + str(len(banks.payload())), dict(payload=banks.payload(), dangerous=True)))
        data = json.loads(files['summary.json'])
        self.assertEqual((data['htotal'], data['vtotal']), (935, 524))

    def test_host_refusal_and_failures_never_retry(self):
        result, calls, files = self.host(risk=False)
        self.assertEqual(result, 3); self.assertEqual(calls, [])
        result, calls, files = self.host(identity='PONG xlle-agent v0.2')
        self.assertEqual(result, 2); self.assertEqual(len(calls), 1)
        for bad in ('RET ffffffff', 'RET 100000000', 'RET abzz0000', 'ERR denied', OSError('timeout')):
            result, calls, files = self.host(reply=bad)
            self.assertEqual(result, 2); self.assertEqual(len(calls), 2)
            self.assertNotIn('summary.json', files)
            if isinstance(bad, str): self.assertIn(bad, files['reply.txt'])


if __name__ == '__main__': unittest.main()
