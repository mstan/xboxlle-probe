#!/usr/bin/env python3
"""Bounded read-only provenance for the live kernel's diagnostic clock.

Resolve two exports from a validated kernel PE image, read their small complete
bodies and identify the captured original port-counter implementation. Each
target payload only loads one aligned DWORD and returns. No original service,
I/O instruction, GPU register, upload, launch or storage operation is sent.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time

from xbox_probe import AgentClient, ProbeError, _require_risk

KERNEL_BASE = 0x80010000
KERNEL_LIMIT = 0x80080000
MAX_READS = 128
MAX_FUNCTION_BYTES = 128
MAX_DECLARED_IMAGE = 0x400000


def read_payload(address):
    if type(address) is not int or address & 3 or not KERNEL_BASE <= address <= KERNEL_LIMIT - 4:
        raise ProbeError('DWORD read is outside the restricted kernel image')
    return b'\xa1' + struct.pack('<I', address) + b'\xc3'


def returned_word(reply):
    if not re.fullmatch(r'RET [0-9a-fA-F]{1,8}', reply):
        raise ProbeError('malformed EXEC return; stop without retry')
    # Instruction bytes can contain all-ones immediates. Metadata/code validity
    # is checked separately; no MMIO register value is being interpreted here.
    return int(reply[4:], 16)


def decoder():
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    except ImportError as error:
        raise ProbeError('Capstone is required; install it before connecting') from error
    return Cs(CS_ARCH_X86, CS_MODE_32)


class KernelReader:
    def __init__(self, read):
        self.read = read
        self.cache = {}
        self.reads = 0
        self.image_size = KERNEL_LIMIT - KERNEL_BASE

    def word(self, address, *, fresh=False):
        read_payload(address)  # Bounds and alignment before the provider.
        if address + 4 > KERNEL_BASE + self.image_size:
            raise ProbeError('read exceeds validated kernel image size')
        if not fresh and address in self.cache:
            return self.cache[address]
        if self.reads == MAX_READS:
            raise ProbeError('kernel clock read budget exhausted')
        self.reads += 1
        value = self.read(address)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ProbeError('invalid DWORD result')
        self.cache[address] = value
        return value

    def rva(self, value, size=4, *, aligned=True):
        if not 0 <= value <= self.image_size - size or (aligned and value & 3):
            raise ProbeError('kernel metadata points outside the validated image')
        return KERNEL_BASE + value


def exports(reader):
    first = reader.word(KERNEL_BASE)
    if first & 0xffff != 0x5a4d:
        raise ProbeError('kernel DOS signature is not established')
    offset = reader.word(KERNEL_BASE + 0x3c)
    if offset & 3 or not 0x40 <= offset <= 0x1000:
        raise ProbeError('kernel PE header offset is invalid')
    pe = KERNEL_BASE + offset
    if reader.word(pe) != 0x4550:
        raise ProbeError('kernel PE signature is invalid')
    coff = reader.word(pe + 4)
    sections = coff >> 16
    if coff & 0xffff != 0x14c or not 1 <= sections <= 16:
        raise ProbeError('kernel machine/section count is unsupported')
    optional_size = reader.word(pe + 20) & 0xffff
    if not 104 <= optional_size <= 256 or optional_size & 3:
        raise ProbeError('kernel optional header size is unsupported')
    if reader.word(pe + 24) & 0xffff != 0x10b:
        raise ProbeError('kernel is not a PE32 image')
    alignment = reader.word(pe + 56)
    if not 32 <= alignment <= 65536 or alignment & (alignment - 1):
        raise ProbeError('kernel section alignment is unsupported')
    image_size = reader.word(pe + 80)
    # Retail Xbox PE sections can use 32-byte alignment and include a larger
    # declared initialization section. Neither expands the permitted read window.
    if image_size % alignment or not 4096 <= image_size <= MAX_DECLARED_IMAGE:
        raise ProbeError('kernel image size is invalid')
    reader.image_size = image_size
    headers_size = reader.word(pe + 84)
    section_table = pe + 24 + optional_size
    if not offset + 24 + optional_size + sections * 40 <= headers_size <= min(image_size, 4096):
        raise ProbeError('kernel section table exceeds its headers')
    if not 1 <= reader.word(pe + 116) <= 16:
        raise ProbeError('kernel export directory count is unsupported')
    directory_rva = reader.word(pe + 120)
    directory_size = reader.word(pe + 124)
    if directory_size < 40:
        raise ProbeError('kernel export directory is too small')
    directory = reader.rva(directory_rva, directory_size)
    ordinal_base = reader.word(directory + 16)
    count = reader.word(directory + 20)
    if not 1 <= ordinal_base <= 126 or not 127 - ordinal_base < count <= 512:
        raise ProbeError('kernel performance exports are not present')
    table = reader.rva(reader.word(directory + 28), count * 4)
    executable = []
    for index in range(sections):
        at = section_table + index * 40
        size = reader.word(at + 8)
        rva = reader.word(at + 12)
        flags = reader.word(at + 36)
        if size:
            start = reader.rva(rva, size, aligned=False)
            if flags & 0x20000000:
                executable.append((start, start + size))
    functions = []
    for ordinal in (126, 127):
        slot = table + (ordinal - ordinal_base) * 4
        rva = reader.word(slot)
        if directory_rva <= rva < directory_rva + directory_size:
            raise ProbeError('forwarded kernel performance export is unsupported')
        entry = reader.rva(rva, 1, aligned=False)
        section = next(((a, b) for a, b in executable if a <= entry < b), None)
        if not section:
            raise ProbeError('kernel performance export is not executable code')
        functions.append(dict(ordinal=ordinal, slot=slot, entry=entry, section=section))
    if functions[0]['entry'] == functions[1]['entry']:
        raise ProbeError('kernel performance exports unexpectedly alias')
    return dict(pe=pe, first=first, header_offset=offset, image_size=image_size,
                functions=functions)


def function_body(reader, function, dis):
    entry = function['entry']
    aligned = entry & ~3
    data = bytearray()
    limit = min(entry + MAX_FUNCTION_BYTES, function['section'][1])
    while aligned + len(data) < limit:
        address = aligned + len(data)
        data.extend(struct.pack('<I', reader.word(address)))
        code = bytes(data[entry - aligned:])
        instructions = list(dis.disasm(code, entry))
        for index, insn in enumerate(instructions):
            if insn.mnemonic == 'ret':
                if insn.op_str:
                    raise ProbeError('kernel clock export unexpectedly consumes arguments')
                end = insn.address + insn.size
                if end > limit:
                    raise ProbeError('kernel clock function crosses its executable section')
                return code[:end - entry], instructions[:index + 1]
    raise ProbeError('kernel clock function has no bounded complete return')


def identify(reader, metadata, bodies):
    counter, frequency = bodies
    frequency_ops = [(i.mnemonic, i.op_str) for i in frequency[1]]
    if frequency_ops != [('mov', 'eax, 0x337f98'), ('xor', 'edx, edx'), ('ret', '')]:
        raise ProbeError('kernel frequency implementation differs from the qualified source')
    ops = [(i.mnemonic, i.op_str) for i in counter[1]]
    # A validation signature for the complete captured original function,
    # allowing relocation of its three kernel globals and its consistency loop.
    # This code does not implement or execute that counter/rollover operation.
    expected = [('push', 'ebx'), ('mov', 'ecx, GLOBAL'), ('mov', 'ebx, GLOBAL'),
                ('cmp', 'ecx, GLOBAL'), ('jne', 'LOOP'), ('mov', 'edx, 0x8008'),
                ('in', 'eax, dx'), ('mov', 'edx, eax'), ('xor', 'edx, ebx'),
                ('and', 'edx, 0x80000000'), ('and', 'eax, 0x7fffffff'),
                ('and', 'ebx, 0x80000000'), ('or', 'eax, ebx'), ('add', 'eax, edx'),
                ('adc', 'ecx, 0'), ('mov', 'edx, ecx'), ('pop', 'ebx'), ('ret', '')]
    if len(ops) != len(expected):
        raise ProbeError('kernel counter implementation differs from the qualified source')
    globals_ = []
    for index, ((mnemonic, operand), (kind, template)) in enumerate(zip(ops, expected)):
        if mnemonic != kind:
            raise ProbeError('kernel counter instruction is outside the qualified source')
        if 'GLOBAL' in template:
            register = template.split(',')[0]
            match = re.fullmatch(register + r', dword ptr \[(0x[0-9a-f]+)\]', operand)
            if not match:
                raise ProbeError('kernel counter global operand is unsupported')
            address = int(match[1], 16)
            reader.rva(address - KERNEL_BASE)
            read_payload(address)  # Globals must also stay in the restricted window.
            globals_.append(address)
        elif template == 'LOOP':
            if int(operand, 16) != counter[1][1].address:
                raise ProbeError('kernel counter consistency branch has changed')
        elif operand != template:
            raise ProbeError('kernel counter operand is outside the qualified source')
    if len(set(globals_)) != 3:
        raise ProbeError('kernel counter consistency globals unexpectedly alias')
    return dict(counter_port=0x8008, frequency_hz=3375000, globals=globals_,
                source_kind='captured-original-port-counter-with-rollover-extension',
                function_sha256=[hashlib.sha256(body).hexdigest() for body, _ in bodies])


def observe(read, dis=None):
    reader = KernelReader(read)
    metadata = exports(reader)
    dis = dis or decoder()
    bodies = [function_body(reader, function, dis) for function in metadata['functions']]
    provenance = identify(reader, metadata, bodies)
    # Planned successful-end stability observations, never a retry after failure.
    for function in metadata['functions']:
        if KERNEL_BASE + reader.word(function['slot'], fresh=True) != function['entry']:
            raise ProbeError('kernel performance export changed during reads')
    if reader.word(KERNEL_BASE, fresh=True) != metadata['first'] or \
            reader.word(KERNEL_BASE + 0x3c, fresh=True) != metadata['header_offset']:
        raise ProbeError('kernel header changed during reads')
    return dict(schema=1, status='clock_implementation_identified', reads=reader.reads,
                provenance=provenance, metadata=metadata,
                functions=[dict(ordinal=f['ordinal'], entry=f['entry'], code_hex=body.hex(),
                                instructions=[dict(address=i.address, mnemonic=i.mnemonic,
                                                   operands=i.op_str) for i in instructions])
                           for f, (body, instructions) in zip(metadata['functions'], bodies)],
                hardware_writes_requested=0, original_services_executed=0,
                automatic_retry=False,
                limits=['Current two clock implementations only, not a complete firmware dump/hash',
                        'Sequential non-atomic memory reads; no counter or frequency service execution',
                        'No counter width/rollover IRQ/cadence calibration or PTIMER effect qualification',
                        'No GPU bootstrap, readiness or capture success'])


def run(args):
    _require_risk(args, 'bounded read-only kernel clock provenance')
    dis = decoder()  # Missing dependency fails before connecting or arming.
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[1]
    if output.is_relative_to(repo) and not output.is_relative_to(repo / 'results'):
        raise ProbeError('inside this repository raw evidence must be under ignored results/')
    output.mkdir(parents=True, exist_ok=False)
    status = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='started', stage='identity', exec_requests_may_have_been_sent=0,
                  hardware_writes_requested=0, automatic_retry=False)
    def checkpoint():
        (output / 'status.json').write_text(json.dumps(status, indent=2) + '\n')
    checkpoint()
    agent = AgentClient(args.host, timeout=8.0)
    try:
        ping = agent.request('PING')
        (output / 'ping.txt').write_text(ping + '\n')
        if ping != 'PONG xboxlle-probe v0.4.0':
            raise ProbeError('unexpected agent; stop before ARM/EXEC')
        with (output / 'reads-raw.jsonl').open('x') as file:
            def read(address):
                payload = read_payload(address)
                status['stage'] = 'kernel_clock_word'
                status['exec_requests_may_have_been_sent'] += 1
                checkpoint()
                before = time.monotonic_ns()
                reply = agent.request('EXEC 6', payload=payload, dangerous=True)
                row = dict(address=address, reply=reply,
                           payload_sha256=hashlib.sha256(payload).hexdigest(),
                           host_interval_ns=[before, time.monotonic_ns()])
                file.write(json.dumps(row) + '\n'); file.flush()
                return returned_word(reply)
            summary = observe(read, dis)
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        status.update(status='observation_complete', reads=summary['reads']); checkpoint()
        print('Kernel clock implementation identified by bounded DWORD reads; zero hardware writes.')
        return 0
    except (OSError, ProbeError, ValueError) as error:
        status.update(status='stopped_human_inspection_required', error=str(error)); checkpoint()
        print('Stopped; private evidence preserved. Human inspection required; no retry.', file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--i-accept-the-risk', action='store_true')
    try:
        return run(parser.parse_args())
    except (OSError, ProbeError, ValueError) as error:
        print('Stopped before hardware commands: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
