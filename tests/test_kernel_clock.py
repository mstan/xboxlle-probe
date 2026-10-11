"""Hardware-free payload, metadata containment and stopped-session checks."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import read_kernel_clock as clock
from xbox_probe import ProbeError

SNAPSHOT = ROOT.parent / 'wt-native-title-pilot/build/blinx/io-boot-18m.ram.bin'
SNAPSHOT_SHA = '31ede2a0e799243b3d39033a0127147b7631950087c05306e64b4203e6ea9ed1'


class CapturedWords:
    """Private owned original source only; no firmware bytes in this test file."""
    def __init__(self):
        self.ram = SNAPSHOT.read_bytes()
        if hashlib.sha256(self.ram).hexdigest() != SNAPSHOT_SHA:
            raise ValueError('unreviewed private source fixture')
        self.overrides = {}
        self.calls = []

    def physical(self, va):
        word = lambda at: struct.unpack_from('<I', self.ram, at)[0]
        pde = word(0xf000 + (va >> 22) * 4)
        if not pde & 1:
            raise ValueError('missing fixture PDE')
        if pde & 128:
            return (pde & 0xffc00000) + (va & 0x3fffff)
        pte = word((pde & 0xfffff000) + ((va >> 12) & 1023) * 4)
        if not pte & 1:
            raise ValueError('missing fixture PTE')
        return (pte & 0xfffff000) + (va & 4095)

    def word(self, address):
        return struct.unpack_from('<I', self.ram, self.physical(address))[0]

    def __call__(self, address):
        clock.read_payload(address)
        self.calls.append(address)
        if address in self.overrides:
            value = self.overrides[address]
            return value(len(self.calls)) if callable(value) else value
        return self.word(address)


class PayloadTests(unittest.TestCase):
    def test_missing_consent_or_decoder_never_connects(self):
        with tempfile.TemporaryDirectory() as temp:
            args = argparse.Namespace(host='authored-placeholder', output=Path(temp)/'fresh', i_accept_the_risk=False)
            with patch.object(clock, 'AgentClient') as agent, self.assertRaises(ProbeError):
                clock.run(args)
            agent.assert_not_called()
            self.assertFalse(args.output.exists())
            args.i_accept_the_risk = True
            with patch.object(clock, 'AgentClient') as agent, patch.object(clock, 'decoder', side_effect=ProbeError('unavailable decoder')), self.assertRaises(ProbeError):
                clock.run(args)
            agent.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'existing'; output.mkdir()
            marker = output/'marker'; marker.write_text('retained evidence')
            args = argparse.Namespace(host='authored-placeholder', output=output, i_accept_the_risk=True)
            with patch.object(clock, 'AgentClient') as agent, patch.object(clock, 'decoder', return_value=object()), self.assertRaises(FileExistsError):
                clock.run(args)
            agent.assert_not_called()
            self.assertEqual(marker.read_text(), 'retained evidence')

    def test_only_restricted_aligned_kernel_dwords(self):
        for address in [clock.KERNEL_BASE, clock.KERNEL_BASE + 0x3c, clock.KERNEL_LIMIT - 4]:
            self.assertEqual(clock.read_payload(address), b'\xa1' + struct.pack('<I', address) + b'\xc3')
        for address in [True, -1, clock.KERNEL_BASE - 4, clock.KERNEL_BASE + 1,
                        clock.KERNEL_LIMIT, 0xfd009200]:
            with self.subTest(address=address), self.assertRaises(ProbeError):
                clock.read_payload(address)

    def test_budget_alignment_and_cache_precede_provider(self):
        calls = []
        reader = clock.KernelReader(lambda at: calls.append(at) or 0x12345678)
        self.assertEqual(reader.word(clock.KERNEL_BASE), 0x12345678)
        self.assertEqual(reader.word(clock.KERNEL_BASE), 0x12345678)
        self.assertEqual(calls, [clock.KERNEL_BASE])
        for address in [clock.KERNEL_BASE + 1, 0xfd009200]:
            with self.assertRaises(ProbeError): reader.word(address)
        self.assertEqual(len(calls), 1)
        for index in range(1, clock.MAX_READS): reader.word(clock.KERNEL_BASE + index * 4)
        with self.assertRaises(ProbeError): reader.word(clock.KERNEL_BASE + clock.MAX_READS * 4)
        self.assertEqual(len(calls), clock.MAX_READS)

    def test_actual_six_byte_payload_preserves_caller(self):
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
            from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
                UC_X86_REG_ESP, UC_X86_REG_EFLAGS, UC_X86_REG_EIP)
        except ImportError:
            self.skipTest('optional instruction executor unavailable')
        for address in [clock.KERNEL_BASE, clock.KERNEL_LIMIT - 4]:
            cpu = Uc(UC_ARCH_X86, UC_MODE_32)
            cpu.mem_map(address & ~4095, 4096)
            cpu.mem_map(0x100000, 4096); cpu.mem_map(0x200000, 4096)
            cpu.mem_write(address, struct.pack('<I', 0x85a731f2))
            cpu.mem_write(0x100000, clock.read_payload(address))
            cpu.mem_write(0x200800, struct.pack('<I', 0x100100))
            cpu.reg_write(UC_X86_REG_ESP, 0x200800)
            registers = [UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                         UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP]
            expected = {reg: 0x21436587 + index for index, reg in enumerate(registers)}
            for reg, value in expected.items(): cpu.reg_write(reg, value)
            cpu.reg_write(UC_X86_REG_EFLAGS, 0x246)
            reads, writes = [], []
            cpu.hook_add(UC_HOOK_MEM_READ, lambda u,a,p,n,v,d: reads.append((p,n)))
            cpu.hook_add(UC_HOOK_MEM_WRITE, lambda u,a,p,n,v,d: writes.append((p,n)))
            cpu.emu_start(0x100000, 0x100100, count=8)
            self.assertEqual(reads, [(address, 4), (0x200800, 4)])
            self.assertEqual(writes, [])
            self.assertEqual(cpu.reg_read(UC_X86_REG_EAX), 0x85a731f2)
            self.assertEqual(cpu.reg_read(UC_X86_REG_ESP), 0x200804)
            self.assertEqual(cpu.reg_read(UC_X86_REG_EIP), 0x100100)
            self.assertEqual(cpu.reg_read(UC_X86_REG_EFLAGS), 0x246)
            for reg, value in expected.items(): self.assertEqual(cpu.reg_read(reg), value)


@unittest.skipUnless(SNAPSHOT.exists(), 'private owned original clock fixture unavailable')
class OriginalSourceTests(unittest.TestCase):
    def setUp(self):
        try: self.dis = clock.decoder()
        except ProbeError: self.skipTest('optional Capstone decoder unavailable')
        self.source = CapturedWords()

    def test_complete_original_export_source(self):
        result = clock.observe(self.source, self.dis)
        self.assertEqual(result['status'], 'clock_implementation_identified')
        self.assertEqual(result['provenance']['counter_port'], 0x8008)
        self.assertEqual(result['provenance']['frequency_hz'], 3375000)
        self.assertEqual(result['original_services_executed'], 0)
        self.assertEqual(result['hardware_writes_requested'], 0)
        self.assertLessEqual(result['reads'], clock.MAX_READS)
        self.assertEqual([f['ordinal'] for f in result['functions']], [126,127])

    def test_bad_metadata_stops_before_derived_read(self):
        reader = clock.KernelReader(self.source)
        metadata = clock.exports(reader)
        pe = metadata['pe']
        cases = [(clock.KERNEL_BASE, 0xffffffff), (clock.KERNEL_BASE + 0x3c, 0x70000000),
                 (pe + 4, 0x1000014c), (pe + 56, 48), (pe + 80, 0xffffffff),
                 (pe + 120, 0xfd009200), (metadata['functions'][0]['slot'], 0xfd009200)]
        for address, bad in cases:
            with self.subTest(address=hex(address)):
                self.source.calls.clear(); self.source.overrides = {address: bad}
                with self.assertRaises(ProbeError): clock.observe(self.source, self.dis)
                self.assertTrue(all(clock.KERNEL_BASE <= at < clock.KERNEL_LIMIT
                                    for at in self.source.calls))
                self.assertNotIn(0xfd009200, self.source.calls)

    def test_changed_code_and_export_stability_stop(self):
        metadata = clock.exports(clock.KernelReader(self.source))
        entry = metadata['functions'][0]['entry']
        original = self.source.word(entry)
        self.source.overrides[entry] = (original & 0xffffff00) | 0x90
        with self.assertRaises(ProbeError): clock.observe(self.source, self.dis)
        slot = metadata['functions'][0]['slot']
        original_slot = self.source.word(slot)
        seen = [0]
        def changed(_):
            seen[0] += 1
            return original_slot if seen[0] == 1 else original_slot + 4
        self.source.overrides = {slot: changed}
        with self.assertRaisesRegex(ProbeError, 'changed during reads'):
            clock.observe(self.source, self.dis)

    def test_partial_evidence_and_no_retry(self):
        source = self.source
        for fault in ['wrong-agent', 'bad-reply', 'timeout', 'success']:
            requests = []
            class FakeAgent:
                def __init__(self, *args, **kwargs): pass
                def request(self, command, *, payload=None, dangerous=False):
                    requests.append((command, payload, dangerous))
                    if command == 'PING':
                        return 'PONG xboxlle-probe v0.2' if fault == 'wrong-agent' else 'PONG xboxlle-probe v0.4.0'
                    self.assert_request(command, payload, dangerous)
                    if fault == 'timeout': raise OSError('authored read timeout')
                    if fault == 'bad-reply': return 'BROKEN'
                    address = struct.unpack_from('<I', payload, 1)[0]
                    return f'RET {source(address):08x}'
                @staticmethod
                def assert_request(command, payload, dangerous):
                    assert command == 'EXEC 6' and dangerous
                    assert len(payload) == 6 and payload[0] == 0xa1 and payload[-1] == 0xc3
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                args = argparse.Namespace(host='authored-loopback-placeholder', output=Path(temp)/'fresh', i_accept_the_risk=True)
                with patch.object(clock, 'AgentClient', FakeAgent), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = clock.run(args)
                self.assertEqual(code, 0 if fault == 'success' else 2)
                status = json.loads((args.output/'status.json').read_text())
                self.assertEqual(status['hardware_writes_requested'], 0)
                if fault == 'wrong-agent':
                    self.assertEqual(len(requests), 1)
                    self.assertEqual(status['exec_requests_may_have_been_sent'], 0)
                elif fault != 'success':
                    self.assertEqual(len(requests), 2)  # PING, one failed read; no retry.
                    self.assertEqual(status['exec_requests_may_have_been_sent'], 1)
                    rows = (args.output/'reads-raw.jsonl').read_text().splitlines()
                    self.assertEqual(len(rows), 1 if fault == 'bad-reply' else 0)
                    self.assertFalse((args.output/'summary.json').exists())


if __name__ == '__main__':
    unittest.main()
