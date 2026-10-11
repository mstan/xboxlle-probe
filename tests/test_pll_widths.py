"""Hardware-free fixed PLL loads, actual instruction effects and stop ordering."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import socketserver
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'host'))
import read_pll_widths as pll

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                                  UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                                  UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS)
except ImportError:
    Uc = None


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode().strip()
        self.server.commands.append(line)
        if line == 'PING':
            self.wfile.write((self.server.identity + '\n').encode()); return
        if line != 'ARM I_ACCEPT_THE_RISK':
            self.wfile.write(b'ERR expected ARM\n'); return
        if not self.server.arm:
            self.wfile.write(b'ERR denied\n'); return
        self.wfile.write(b'ARMED\n'); self.wfile.flush()
        line = self.rfile.readline().decode().strip()
        self.server.commands.append(line)
        if line not in ('EXEC 6', 'EXEC 8'):
            self.wfile.write(b'ERR unexpected EXEC length\n'); return
        payload = self.rfile.read(int(line.split()[1]))
        self.server.payloads.append(payload)
        index = len(self.server.payloads) - 1
        _, address, width, _ = pll.OPERATIONS[index]
        self.assert_payload(payload, address, width)
        word = self.server.values[address & ~3]
        value = word if width == 4 else (word >> 8) & 0xff
        reply = self.server.replies.get(index, 'RET ' + format(value, 'x'))
        self.wfile.write((reply + '\n').encode())

    def assert_payload(self, payload, address, width):
        expected = (b'\xa1' if width == 4 else b'\x0f\xb6\x05') + struct.pack('<I', address) + b'\xc3'
        if payload != expected:
            self.server.invalid_payloads.append(payload)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.commands, self.payloads, self.invalid_payloads = [], [], []
        self.identity = 'PONG xboxlle-probe v0.4.0'; self.arm = True
        self.replies = {}
        self.values = {0xfd680500: 0x00111c01, 0xfd680504: 0, 0xfd680508: 0x0003c20d}


class PllWidthTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start(); self.addCleanup(self.close_server)
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'observation'

    def close_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def run_batch(self, risk=True):
        original = pll.AgentClient
        def client(host, timeout):
            self.assertEqual(host, '127.0.0.1')
            return original(host, port=self.server.server_address[1], timeout=timeout)
        with patch.object(pll, 'AgentClient', side_effect=client), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return pll.run(argparse.Namespace(host='127.0.0.1', output=self.output, i_accept_the_risk=risk))

    def test_fixed_batch_uses_both_real_protocol_lengths(self):
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.server.payloads), 9)
        self.assertFalse(self.server.invalid_payloads)
        self.assertEqual(self.server.commands, ['PING'] +
                         [part for _ in range(3) for part in ('ARM I_ACCEPT_THE_RISK', 'EXEC 6',
                          'ARM I_ACCEPT_THE_RISK', 'EXEC 8', 'ARM I_ACCEPT_THE_RISK', 'EXEC 6')])
        summary = json.loads((self.output / 'summary.json').read_text())
        self.assertEqual(summary['reads'], 9)
        self.assertEqual(summary['hardware_writes_requested'], 0)
        self.assertEqual([row['width'] for row in summary['observations']], [4, 1, 4] * 3)

    def test_preconnect_and_fixed_address_guards(self):
        with self.assertRaises(pll.ProbeError): self.run_batch(risk=False)
        self.assertFalse(self.output.exists()); self.assertFalse(self.server.commands)
        self.output.mkdir()
        with self.assertRaises(FileExistsError): self.run_batch()
        self.assertFalse(self.server.commands)
        for address, width in ((0xfd680500, 1), (0xfd680501, 4), (0xfd680502, 2),
                               (0xfd001804, 4), (0xfd680505, True), (True, 1)):
            with self.subTest(address=address, width=width), self.assertRaises(pll.ProbeError):
                pll.read_payload(address, width)

    def test_wrong_identity_and_refused_arm_do_not_execute(self):
        self.server.identity = 'PONG xlle-agent v0.2'
        self.assertEqual(self.run_batch(), 2); self.assertEqual(self.server.commands, ['PING'])
        self.server.identity = 'PONG xboxlle-probe v0.4.0'; self.server.commands.clear()
        self.server.arm = False; self.output = self.output.parent / 'arm-denied'
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(self.server.commands, ['PING', 'ARM I_ACCEPT_THE_RISK'])
        self.assertFalse(self.server.payloads)

    def test_bad_reply_mismatch_and_changed_context_stop_immediately(self):
        # The first failing load is the last command, with its raw reply retained.
        for index, reply in ((0, 'RET ffffffff'), (1, 'RET 100'), (1, 'RET 1d'),
                             (2, 'RET 111c02'), (4, 'RET 100000000'), (5, 'ERR fault')):
            with self.subTest(index=index, reply=reply):
                self.server.commands.clear(); self.server.payloads.clear(); self.server.replies = {index: reply}
                self.output = self.output.parent / ('failure-' + str(index) + '-' + reply.replace(' ', '_'))
                self.assertEqual(self.run_batch(), 2)
                self.assertEqual(len(self.server.payloads), index + 1)
                raw = [json.loads(line) for line in (self.output / 'reads-raw.jsonl').read_text().splitlines()]
                self.assertEqual(raw[-1]['reply'], reply)
                status = json.loads((self.output / 'status.json').read_text())
                self.assertEqual(status['status'], 'stopped_human_inspection_required')
                self.assertEqual(status['exec_requests_may_have_been_sent'], index + 1)
                self.assertFalse((self.output / 'summary.json').exists())

    def test_timeout_retains_pending_attempt_without_retry(self):
        class FailedAgent:
            commands = []
            def __init__(self, *args, **kwargs): pass
            def request(self, command, **kwargs):
                self.commands.append(command)
                if command == 'PING': return 'PONG xboxlle-probe v0.4.0'
                raise pll.ProbeError('timeout after request')
        with patch.object(pll, 'AgentClient', FailedAgent), redirect_stderr(io.StringIO()):
            self.assertEqual(pll.run(argparse.Namespace(host='127.0.0.1', output=self.output, i_accept_the_risk=True)), 2)
        self.assertEqual(FailedAgent.commands, ['PING', 'EXEC 6'])
        status = json.loads((self.output / 'status.json').read_text())
        self.assertEqual(status['exec_requests_may_have_been_sent'], 1)
        self.assertEqual(status['complete_validated_reads'], 0)
        self.assertFalse((self.output / 'summary.json').exists())

    @unittest.skipUnless(Uc is not None, 'optional Unicorn instruction audit unavailable')
    def test_actual_loads_touch_only_listed_memory_and_preserve_caller_state(self):
        for _, address, width, _ in pll.OPERATIONS:
            with self.subTest(address=address, width=width):
                cpu = Uc(UC_ARCH_X86, UC_MODE_32)
                cpu.mem_map(0x10000, 0x1000); cpu.mem_map(0x20000, 0x1000)
                cpu.mem_map(address & ~0xfff, 0x1000)
                cpu.mem_write(0x10000, pll.read_payload(address, width))
                cpu.mem_write(address & ~3, struct.pack('<I', 0xa57edb21))
                cpu.mem_write(0x20800, struct.pack('<I', 0x10100))
                regs = [(UC_X86_REG_EBX, 0x123), (UC_X86_REG_ECX, 0x234), (UC_X86_REG_EDX, 0x345),
                        (UC_X86_REG_ESI, 0x456), (UC_X86_REG_EDI, 0x567), (UC_X86_REG_EBP, 0x678),
                        (UC_X86_REG_EFLAGS, 0x246)]
                for reg, value in regs: cpu.reg_write(reg, value)
                cpu.reg_write(UC_X86_REG_ESP, 0x20800); cpu.reg_write(UC_X86_REG_EAX, 0xffffffff)
                reads, writes = [], []
                cpu.hook_add(UC_HOOK_MEM_READ, lambda uc, access, a, n, v, data: reads.append((a, n)))
                cpu.hook_add(UC_HOOK_MEM_WRITE, lambda uc, access, a, n, v, data: writes.append((a, n)))
                cpu.emu_start(0x10000, 0x10100, count=3)
                self.assertEqual(reads, [(address, width), (0x20800, 4)])
                self.assertFalse(writes)
                self.assertEqual(cpu.reg_read(UC_X86_REG_EAX), 0xa57edb21 if width == 4 else 0xdb)
                self.assertEqual(cpu.reg_read(UC_X86_REG_ESP), 0x20804)
                self.assertEqual(cpu.reg_read(UC_X86_REG_EIP), 0x10100)
                for reg, value in regs: self.assertEqual(cpu.reg_read(reg), value)


if __name__ == '__main__':
    unittest.main()
