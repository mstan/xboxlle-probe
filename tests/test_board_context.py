"""Hardware-free proof of every fixed payload and host stop behavior."""
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
import read_board_context as board
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_INSN
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                              UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                              UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EFLAGS,
                              UC_X86_INS_IN, UC_X86_INS_OUT)


class BoardTests(unittest.TestCase):
    def test_actual_payload_reads_and_preserves_registers(self):
        for name, payload, bits in board.OPERATIONS:
            with self.subTest(name=name):
                uc = Uc(UC_ARCH_X86, UC_MODE_32)
                uc.mem_map(0x1000, 0x1000); uc.mem_write(0x1000, payload)
                uc.mem_map(0x7000, 0x2000)
                uc.mem_write(0x8000, struct.pack('<I', 0x1800))
                uc.reg_write(UC_X86_REG_ESP, 0x8000)
                preserved = {UC_X86_REG_EBX: 0x12121212, UC_X86_REG_ECX: 0x34343434,
                             UC_X86_REG_EDX: 0x56565656, UC_X86_REG_ESI: 0x78787878,
                             UC_X86_REG_EDI: 0x90909090, UC_X86_REG_EBP: 0xabababab,
                             UC_X86_REG_EFLAGS: 0x247}
                for reg, value in preserved.items(): uc.reg_write(reg, value)
                writes = []; reads = []; ports = []; outputs = []
                uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, a, addr, size, value, data: writes.append((addr, size)))
                uc.hook_add(UC_HOOK_MEM_READ, lambda u, a, addr, size, value, data: reads.append((addr, size)))
                if bits == 32:
                    address = struct.unpack('<I', payload[1:5])[0]
                    uc.mem_map(address & ~0xfff, 0x1000)
                    uc.mem_write(address, struct.pack('<I', 0x11223344))
                def incoming(u, port, size, data):
                    ports.append((port, size)); return 5
                uc.hook_add(UC_HOOK_INSN, incoming, None, 1, 0, UC_X86_INS_IN)
                uc.hook_add(UC_HOOK_INSN, lambda u, port, size, value, data: outputs.append(port),
                            None, 1, 0, UC_X86_INS_OUT)
                uc.emu_start(0x1000, 0x1800, count=32)
                self.assertEqual(uc.reg_read(UC_X86_REG_EAX), 0x11223344 if bits == 32 else 5)
                self.assertEqual(uc.reg_read(UC_X86_REG_ESP), 0x8004)
                for reg, value in preserved.items(): self.assertEqual(uc.reg_read(reg), value)
                self.assertEqual(outputs, [])
                if bits == 32:
                    self.assertEqual(reads, [(address, 4), (0x8000, 4)])
                    self.assertEqual(writes, []); self.assertEqual(ports, [])
                else:
                    self.assertEqual(ports, [(0x80cf, 1)])
                    self.assertEqual(writes, [(0x7ffc, 4), (0x7ff8, 4)])
                    self.assertEqual(reads, [(0x7ff8, 4), (0x7ffc, 4), (0x8000, 4)])

    def run_host(self, replacements=None, risk=True, existing=False):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'session'
            if existing: output.mkdir()
            replies = ['PONG xboxlle-probe v0.4.0', 'RET 0', 'RET 10020000', 'RET 5', 'RET 0', 'RET 0']
            for index, value in (replacements or {}).items(): replies[index] = value
            calls = []
            class Agent:
                def __init__(self, host, timeout): pass
                def request(self, command, **kwargs):
                    calls.append((command, kwargs))
                    result = replies[len(calls) - 1]
                    if isinstance(result, Exception): raise result
                    return result
            with patch.object(board, 'AgentClient', Agent), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                args = argparse.Namespace(host='127.0.0.1', output=output, i_accept_the_risk=risk)
                try: result = board.run(args)
                except (OSError, board.ProbeError): result = 3
            files = {item.name: item.read_text() for item in output.glob('*')} if output.exists() else {}
            return result, calls, files

    def test_complete_fixed_list_and_dangerous_arm_path(self):
        result, calls, files = self.run_host()
        self.assertEqual(result, 0)
        self.assertEqual(calls[0], ('PING', {}))
        for call, (_, payload, _) in zip(calls[1:], board.OPERATIONS):
            self.assertEqual(call, ('EXEC ' + str(len(payload)), dict(payload=payload, dangerous=True)))
        self.assertEqual(len(calls), 6)
        summary = json.loads(files['summary.json'])
        self.assertEqual(summary['reads'], 5); self.assertEqual(summary['hardware_writes_requested'], 0)

    def test_no_authorization_or_existing_output_cannot_connect(self):
        for kwargs in (dict(risk=False), dict(existing=True)):
            result, calls, files = self.run_host(**kwargs)
            self.assertEqual(result, 3); self.assertEqual(calls, [])

    def test_wrong_identity_stops_before_exec(self):
        result, calls, files = self.run_host({0: 'PONG xlle-agent v0.2'})
        self.assertEqual(result, 2); self.assertEqual(len(calls), 1)

    def test_failure_is_saved_and_never_retried(self):
        for bad in ('RET ffffffff', 'RET 100000000', 'ERR denied', 'RET ff', 'RET 100', OSError('timeout')):
            result, calls, files = self.run_host({3: bad})
            self.assertEqual(result, 2); self.assertEqual(len(calls), 4)
            self.assertNotIn('summary.json', files)
            self.assertEqual(json.loads(files['status.json'])['status'], 'stopped_human_inspection_required')
            if isinstance(bad, str): self.assertIn(bad, files['reads-raw.jsonl'])

    def test_changed_or_pending_av_cannot_qualify(self):
        for replacements, count in (({1: 'RET 1'}, 2), ({5: 'RET 11'}, 6)):
            result, calls, files = self.run_host(replacements)
            self.assertEqual(result, 2); self.assertEqual(len(calls), count)
            self.assertNotIn('summary.json', files)


if __name__ == '__main__':
    unittest.main()
