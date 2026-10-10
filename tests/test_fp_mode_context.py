"""Execute fixed x86 reads and prove host stops without extra hardware commands."""
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
import read_fp_mode_context as context
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP


class ModeContextTests(unittest.TestCase):
    def test_actual_bytes_only_load_listed_dword_and_return(self):
        allowed = {0xfd6806a0, 0xfd680848, 0xfd680880, 0xfd680884,
                   0xfd680888, 0xfd680834, 0xfd680838, 0xfd680820}
        self.assertEqual({address for _, address, _ in context.OPERATIONS}, allowed)
        for address in allowed:
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            uc.mem_map(0x1000, 0x1000); uc.mem_write(0x1000, context.read_payload(address))
            uc.mem_map(0x7000, 0x2000); uc.mem_write(0x8000, struct.pack('<I', 0x1800))
            uc.reg_write(UC_X86_REG_ESP, 0x8000)
            uc.mem_map(address & ~0xfff, 0x1000); uc.mem_write(address, struct.pack('<I', 0x34567890))
            reads = []; writes = []
            uc.hook_add(UC_HOOK_MEM_READ, lambda u, a, addr, size, value, data: reads.append((addr, size)))
            uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, a, addr, size, value, data: writes.append((addr, size)))
            uc.emu_start(0x1000, 0x1800, count=3)
            self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0x34567890)
            self.assertEqual(reads, [(address, 4), (0x8000, 4)]); self.assertEqual(writes, [])

    def host(self, change=None, risk=True):
        calls = []
        replies = ['PONG xboxlle-probe v0.4.0'] + [
            'RET '+format(expected if expected is not None else 0, 'x')
            for _, _, expected in context.OPERATIONS]
        if change:
            replies[change[0]] = change[1]
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
                except context.ProbeError:
                    result = 3
            files = {item.name: item.read_text() for item in output.glob('*')}
        return result, calls, files

    def test_complete_fixed_batch_uses_arm_path(self):
        result, calls, files = self.host()
        self.assertEqual(result, 0); self.assertEqual(len(calls), 11)
        for call, (_, address, _) in zip(calls[1:], context.OPERATIONS):
            self.assertEqual(call, ('EXEC 6', dict(payload=context.read_payload(address), dangerous=True)))
        self.assertEqual(json.loads(files['summary.json'])['hardware_writes_requested'], 0)

    def test_risk_gate_and_closed_addresses(self):
        self.assertEqual(self.host(risk=False)[:2], (3, []))
        for address in (0, 0xfd68088c, 0xfe830ffc, True):
            with self.assertRaises(context.ProbeError): context.read_payload(address)

    def test_wrong_identity_never_executes(self):
        result, calls, _ = self.host((0, 'PONG xlle-agent v0.2'))
        self.assertEqual(result, 2); self.assertEqual(len(calls), 1)

    def test_malformed_timeout_all_ones_stop_once(self):
        for reply in ('RET ffffffff', 'RET 100000000', 'ERR denied', OSError('timeout')):
            result, calls, files = self.host((4, reply))
            self.assertEqual(result, 2); self.assertEqual(len(calls), 5)
            self.assertNotIn('summary.json', files)
            self.assertEqual(json.loads(files['status.json'])['status'], 'stopped_human_inspection_required')

    def test_endpoint_or_restored_field_change_stops(self):
        for index, reply in ((1, 'RET 1'), (2, 'RET 10000111'), (6, 'RET 1'),
                             (9, 'RET 10000111'), (10, 'RET 0')):
            result, calls, files = self.host((index, reply))
            self.assertEqual(result, 2); self.assertEqual(len(calls), index+1)
            self.assertNotIn('summary.json', files)


if __name__ == '__main__':
    unittest.main()
