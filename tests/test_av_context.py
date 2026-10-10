"""No Xbox access: loopback accident guards and actual x86 payload effects."""
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
import read_av_context as context

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                                  UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
                                  UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EFLAGS)
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
        if not self.server.allow_arm:
            self.wfile.write(b'ERR denied\n'); return
        self.wfile.write(b'ARMED\n'); self.wfile.flush()
        line = self.rfile.readline().decode().strip()
        self.server.commands.append(line)
        if line != 'EXEC 6':
            self.wfile.write(b'ERR expected EXEC 6\n'); return
        payload = self.rfile.read(6)
        self.server.payloads.append(payload)
        index = len(self.server.payloads) - 1
        address = struct.unpack('<I', payload[1:5])[0]
        value = 0 if address == 0xfd6806a0 else 0x12345678
        if index in self.server.replies:
            reply = self.server.replies[index]
        else:
            reply = 'RET ' + format(value, 'x')
        self.wfile.write((reply + '\n').encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.commands = []; self.payloads = []; self.replies = {}
        self.identity = 'PONG xboxlle-probe v0.4.0'; self.allow_arm = True


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'context'

    def close_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def run_batch(self, risk=True):
        original = context.AgentClient
        def client(host, timeout):
            self.assertEqual(host, '127.0.0.1')
            return original(host, port=self.server.server_address[1], timeout=timeout)
        with patch.object(context, 'AgentClient', side_effect=client), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return context.run(argparse.Namespace(host='127.0.0.1', output=self.output, i_accept_the_risk=risk))

    def test_full_batch_is_fixed_and_armed(self):
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.server.payloads), 23)
        self.assertEqual(self.server.commands, ['PING'] + ['ARM I_ACCEPT_THE_RISK', 'EXEC 6'] * 23)
        expected = [address for _, address in context.REGISTERS] + [0xfd6806a0]
        self.assertEqual([struct.unpack('<I', item[1:5])[0] for item in self.server.payloads], expected)
        summary = json.loads((self.output / 'summary.json').read_text())
        self.assertEqual(summary['reads'], 23)
        self.assertEqual(summary['hardware_writes_requested'], 0)
        self.assertEqual(summary['distinct_addresses'], 22)

    def test_no_risk_flag_has_no_connection(self):
        with self.assertRaises(context.ProbeError): self.run_batch(risk=False)
        self.assertFalse(self.server.commands)
        self.assertFalse(self.output.exists())

    def test_wrong_agent_stops_before_arming(self):
        self.server.identity = 'PONG xlle-agent v0.2'
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(self.server.commands, ['PING'])

    def test_refused_arm_sends_no_payload(self):
        self.server.allow_arm = False
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(self.server.commands, ['PING', 'ARM I_ACCEPT_THE_RISK'])
        self.assertFalse(self.server.payloads)

    def test_malformed_reply_is_saved_and_stops(self):
        self.server.replies[2] = 'RET 100000000'
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(len(self.server.payloads), 3)
        raw = (self.output / 'reads-raw.jsonl').read_text()
        self.assertIn('RET 100000000', raw)
        self.assertFalse((self.output / 'summary.json').exists())

    def test_all_ones_stops_without_retry(self):
        self.server.replies[1] = 'RET ffffffff'
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(len(self.server.payloads), 2)

    def test_pending_initial_av_stops_before_context(self):
        self.server.replies[0] = 'RET 1'
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(len(self.server.payloads), 1)

    def test_changed_final_av_is_not_success(self):
        self.server.replies[22] = 'RET 11'
        self.assertEqual(self.run_batch(), 2)
        self.assertEqual(len(self.server.payloads), 23)
        self.assertFalse((self.output / 'summary.json').exists())

    def test_existing_session_is_not_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError): self.run_batch()
        self.assertFalse(self.server.commands)

    def test_nonfixed_address_is_rejected(self):
        for address in (0, 0xfe801510, 0xffffffff, True):
            with self.assertRaises(context.ProbeError): context.read_payload(address)

    @unittest.skipIf(Uc is None, 'actual payload validation requires offline Unicorn')
    def test_actual_payload_has_one_dword_load_and_no_stores(self):
        for name, address in context.REGISTERS:
            with self.subTest(register=name):
                cpu = Uc(UC_ARCH_X86, UC_MODE_32)
                code, stack, stop = 0x100000, 0x200000, 0x100100
                cpu.mem_map(code, 4096); cpu.mem_map(stack, 4096); cpu.mem_map(0xfd680000, 4096)
                cpu.mem_write(code, context.read_payload(address))
                cpu.mem_write(stack + 512, struct.pack('<I', stop))
                cpu.mem_write(address, struct.pack('<I', 0x87654321))
                cpu.reg_write(UC_X86_REG_ESP, stack + 512)
                preserved = {reg: 0x11110000 + index for index, reg in enumerate(
                    (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
                     UC_X86_REG_EDI, UC_X86_REG_EBP))}
                for reg, value in preserved.items(): cpu.reg_write(reg, value)
                cpu.reg_write(UC_X86_REG_EFLAGS, 0x202)
                reads, writes = [], []
                cpu.hook_add(UC_HOOK_MEM_READ, lambda uc, access, addr, size, value, user: reads.append((addr, size)))
                cpu.hook_add(UC_HOOK_MEM_WRITE, lambda uc, access, addr, size, value, user: writes.append((addr, size)))
                cpu.emu_start(code, stop, count=3)
                self.assertEqual(reads, [(address, 4), (stack + 512, 4)])
                self.assertFalse(writes)
                self.assertEqual(cpu.reg_read(UC_X86_REG_EAX), 0x87654321)
                self.assertEqual(cpu.reg_read(UC_X86_REG_ESP), stack + 516)
                self.assertEqual(cpu.reg_read(UC_X86_REG_EFLAGS), 0x202)
                for reg, value in preserved.items(): self.assertEqual(cpu.reg_read(reg), value)


if __name__ == '__main__':
    unittest.main()
