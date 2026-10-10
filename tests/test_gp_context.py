"""Hardware-free fixed-load proof and stop/no-retry checks for GP context."""
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
import read_gp_context as context
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP


class GpContextTests(unittest.TestCase):
    def test_actual_loads_only_touch_six_fixed_registers(self):
        allowed = {0xfd6806a0, 0xfe83fffc, 0xfe802040, 0xfe8020d4, 0xfe802044, 0xfe8020d8}
        self.assertEqual({address for _, address in context.OPERATIONS}, allowed)
        for address in allowed:
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            uc.mem_map(0x1000, 0x1000); uc.mem_write(0x1000, context.read_payload(address))
            uc.mem_map(0x7000, 0x2000); uc.mem_write(0x8000, struct.pack('<I', 0x1800))
            uc.reg_write(UC_X86_REG_ESP, 0x8000)
            uc.mem_map(address & ~0xfff, 0x1000); uc.mem_write(address, struct.pack('<I', 0x12345678))
            reads = []; writes = []
            uc.hook_add(UC_HOOK_MEM_READ, lambda u, a, addr, size, value, data: reads.append((addr, size)))
            uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, a, addr, size, value, data: writes.append((addr, size)))
            uc.emu_start(0x1000, 0x1800, count=3)
            self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0x12345678)
            self.assertEqual(reads, [(address, 4), (0x8000, 4)]); self.assertEqual(writes, [])

    def host(self, change=None, risk=True):
        replies = ['PONG xboxlle-probe v0.4.0', 'RET 11', 'RET 0', 'RET 1000',
                   'RET 1', 'RET 2000', 'RET 3', 'RET 0', 'RET 11']; calls = []
        if change: replies[change[0]] = change[1]
        class Agent:
            def __init__(self, host, timeout): pass
            def request(self, command, **kwargs):
                calls.append((command, kwargs)); result = replies[len(calls)-1]
                if isinstance(result, Exception): raise result
                return result
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'context'
            with patch.object(context, 'AgentClient', Agent), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    result = context.run(argparse.Namespace(host='127.0.0.1', output=output, i_accept_the_risk=risk))
                except context.ProbeError: result = 3
            files = {item.name: item.read_text() for item in output.glob('*')}
        return result, calls, files

    def test_fixed_batch_arms_and_never_dereferences_sg(self):
        result, calls, files = self.host()
        self.assertEqual(result, 0); self.assertEqual(len(calls), 9)
        for call, (_, address) in zip(calls[1:], context.OPERATIONS):
            self.assertEqual(call, ('EXEC 6', dict(payload=context.read_payload(address), dangerous=True)))
        self.assertEqual(json.loads(files['summary.json'])['hardware_writes_requested'], 0)

    def test_gate_and_closed_address_list(self):
        self.assertEqual(self.host(risk=False)[:2], (3, []))
        for address in (0, True, 0xfe830000, 0xfe83a000, 0xfe840000):
            with self.assertRaises(context.ProbeError): context.read_payload(address)

    def test_wrong_identity_never_executes(self):
        result, calls, _ = self.host((0, 'PONG xlle-agent v0.2'))
        self.assertEqual(result, 2); self.assertEqual(len(calls), 1)

    def test_failures_stop_without_extra_requests(self):
        for reply in ('RET ffffffff', 'RET 100000000', 'ERR denied', OSError('timeout')):
            result, calls, files = self.host((3, reply))
            self.assertEqual(result, 2); self.assertEqual(len(calls), 4)
            self.assertNotIn('summary.json', files)
            self.assertEqual(json.loads(files['status.json'])['status'], 'stopped_human_inspection_required')

    def test_changed_reset_or_av_cannot_qualify(self):
        for index, reply in ((1, 'RET 0'), (7, 'RET 3'), (8, 'RET 10')):
            result, calls, files = self.host((index, reply))
            self.assertEqual(result, 2); self.assertEqual(len(calls), index+1)
            self.assertNotIn('summary.json', files)


if __name__ == '__main__': unittest.main()
