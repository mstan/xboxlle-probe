"""Actual compiled diagnostic x86 against an independent RAM/MMIO producer.

The GPU producer emits arbitrary tagged data: this proves delivery and ordering,
NOT hardware pixels or a noise algorithm. Target SDK COFF is separately built.
No console, socket, device, default agent, or SDK file is changed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = None
EXE = None
RECORDS = []
PUT, GET = 0xfd800040, 0xfd800044
STATUS, NSOURCE = 0xfd400700, 0xfd400108
INDEX, DATA, CACHE = 0xfd400750, 0xfd400754, 0xfd100410


def u32(data):
    return struct.unpack('<I', bytes(data))[0]


class Machine:
    def __init__(self, fault=0, hardware_fault=''):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        pe = pefile.PE(str(EXE))
        base = pe.OPTIONAL_HEADER.ImageBase
        self.uc.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        self.uc.mem_write(base, pe.get_memory_mapped_image())
        self.symbols = {s.name.decode(): base+s.address
                        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
        pe.close()  # Release the Windows file mapping before fixture cleanup.
        for address, size in [(0x100000, 0x20000), (0x81000000, 0x2000),
                              (0x81200000, 0x40000), (0x81300000, 0x12c000),
                              (0xfd100000, 0x1000), (0xfd400000, 0x1000),
                              (0xfd800000, 0x1000)]:
            self.uc.mem_map(address, size)
        self.uc.mem_write(0x81000000, b'\xa5' * 0x2000)
        self.uc.mem_write(0x81200000, b'\x5a' * 0x40000)
        self.uc.mem_write(0x81300000, struct.pack('<I', 0xcafebabe) * (640*480))
        self.hardware_fault = hardware_fault
        self.writes, self.reads, self.jobs = [], [], []
        self.index, self.banks, self.cursor = 0, {0xe00054:0x51e0,0xdf000c:0x51df}, 0x01200000
        self.selector_writes=0
        self.cache, self.gpu_registers, self.vertices = 0, {}, []
        self.draws, self.copies, self.expected_pixels = 0, 0, []
        self.read_occurrences = {}
        self.uc.hook_add(UC_HOOK_MEM_READ, self.read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.call('model_prepare', fault)

    def call(self, name, *args):
        stack = 0x11f000
        self.uc.mem_write(stack, struct.pack('<'+'I'*(1+len(args)),
                                           0x100000, *args))
        self.uc.reg_write(UC_X86_REG_ESP, stack)
        self.uc.reg_write(UC_X86_REG_EIP, self.symbols[name])
        self.uc.emu_start(self.symbols[name], 0x100000, count=2000000)
        if self.uc.reg_read(UC_X86_REG_EIP) != 0x100000:
            raise AssertionError('actual x86 failed finite instruction ceiling')
        return self.uc.reg_read(UC_X86_REG_EAX)

    def word(self, address):
        return u32(self.uc.mem_read(address, 4))

    def set_word(self, address, value):
        self.uc.mem_write(address, struct.pack('<I', value & 0xffffffff))

    def read(self, uc, access, address, size, value, user):
        if not 0xfd000000 <= address < 0xfe000000:
            return
        assert size == 4
        self.reads.append(address)
        self.read_occurrences[address] = self.read_occurrences.get(address, 0)+1
        if address == INDEX:
            value = self.index ^ (4 if self.hardware_fault == 'index' else 0)
            if self.hardware_fault=='reselect' and self.selector_writes==2:
                value ^= 4
        elif address == DATA:
            value = self.banks.get(self.index, 0)
            if self.hardware_fault == 'data':
                value ^= 1
            self.index += 4
        elif address == CACHE:
            value = self.cache & ~0x10000
            if self.cache and self.hardware_fault == 'cache-bits':
                value ^= 4
            if self.cache and self.hardware_fault == 'cache-busy':
                value = self.cache
        elif address == PUT:
            value = self.cursor
            if self.jobs and self.hardware_fault == 'put':
                value ^= 4
        elif address == GET:
            value = 0x01200000 if self.hardware_fault == 'get-stuck' else self.cursor
        elif address == NSOURCE:
            value = 1 if self.jobs and self.hardware_fault == 'gpu-error' else 0
        elif address == STATUS:
            value = 0
        else:
            raise AssertionError(f'unreviewed MMIO read {address:08x}')
        self.set_word(address, value)

    def write(self, uc, access, address, size, value, user):
        if not 0xfd000000 <= address < 0xfe000000:
            return
        assert size == 4
        self.writes.append((address, value))
        if address == INDEX:
            self.selector_writes += 1
            self.index = value
        elif address == DATA:
            assert self.index in (0xe00050, 0xdf0008) and value in (0, 1)
            self.banks[self.index] = value
            self.index += 8 if self.hardware_fault=='write-increment' else 4
        elif address == CACHE:
            assert value == 0x10000
            self.cache = value
        elif address == PUT:
            assert self.cursor < value <= 0x01240000 and not value & 3
            old = self.cursor
            self.cursor = value
            self.jobs.append((old, value))
            self.consume(old, value)
        else:
            raise AssertionError(f'unreviewed MMIO write {address:08x}')

    def consume(self, old, new):
        raw = bytes(self.uc.mem_read(0x80000000+old, new-old))
        pairs = list(struct.iter_unpack('<II', raw))
        assert all(header >> 18 == 1 for header, _ in pairs)
        for header, value in pairs:
            subchannel = (header >> 13) & 7
            method = header & 0x1fff
            assert subchannel in (0, 2)
            self.gpu_registers[(subchannel, method)] = value
            if subchannel == 0:
                if method == 0x17fc and value == 5:
                    self.vertices = []
                elif method == 0x1818:
                    self.vertices.append(value)
                elif method == 0x17fc and value == 0:
                    self.render()
            elif method == 0x328:
                self.copy()

    def render(self):
        def reg(offset):
            return self.gpu_registers[(0, offset)]
        assert reg(0x1b04) == 0x02210c29
        assert reg(0x1b00) == 0x01000000
        assert reg(0x1b08) == 0x00030303
        assert reg(0x1b0c) == 0x40000000
        assert reg(0x1b14) == 0x01010000
        assert reg(0x200) == reg(0x204) == 8 << 16
        assert reg(0x1e94) == 2 and reg(0x1760) == reg(0x1764) == 0x42
        assert reg(0xac0) == 0x08200000 and reg(0x260) == 0x18200000
        assert reg(0x1e40) == reg(0xaa0) == 0xc00
        assert reg(0x358) == 0x01010101
        program = [reg(0xb00+i*4) for i in range(8)]
        assert program == [0, 0x20001b, 0x8000000, 0xf800,
                           0, 0x20021b, 0x8000000, 0xf849]
        expected = [(0,0,0,0), (0x41000000,0,0x3f800000,0),
                    (0,0x41000000,0,0x3f800000), (0,0x41000000,0,0x3f800000),
                    (0x41000000,0,0x3f800000,0),
                    (0x41000000,0x41000000,0x3f800000,0x3f800000)]
        expected = [lane for x,y,u,v in expected
                    for lane in (x,y,0,0x3f800000,u,v,0,0x3f800000)]
        assert self.vertices == expected
        expected_control = (0,1,1,0)[self.draws]
        assert self.banks == {0xe00050:expected_control,0xdf0008:expected_control,
                              0xe00054:0x51e0,0xdf000c:0x51df}
        # Independent arbitrary producer, deliberately no noise/pixel equation.
        pixels = [0x80000000 | self.draws << 16 | p for p in range(64)]
        for row in range(8):
            self.uc.mem_write(0x81300000+row*2560,
                             struct.pack('<8I', *pixels[row*8:row*8+8]))
        self.expected_pixels.append(pixels)
        self.draws += 1

    def copy(self):
        reg = lambda offset: self.gpu_registers[(2, offset)]
        assert reg(0x184) == reg(0x188) == 3
        assert reg(0x30c) == 0x01300000
        assert reg(0x310) == 0x01001000+self.copies*256
        assert reg(0x314) == 2560 and reg(0x318) == 32
        assert reg(0x31c) == 32 and reg(0x320) == 8
        assert reg(0x324) == 0x101 and reg(0x328) == 0
        for row in range(8):
            data = self.uc.mem_read(0x80000000+reg(0x30c)+row*reg(0x314), reg(0x31c))
            self.uc.mem_write(0x80000000+reg(0x310)+row*reg(0x318), bytes(data))
        self.copies += 1

    def result(self):
        raw = self.uc.mem_read(self.symbols['noise_pair_result'], 1104)
        return struct.unpack('<276I', raw)

    def record(self, name, status):
        RECORDS.append(dict(name=name, status=status, allocations=self.word(self.symbols['model_allocations']),
                            locks=self.word(self.symbols['model_locks']), jobs=len(self.jobs),
                            draws=self.draws, copies=self.copies, mmio_writes=self.writes,
                            mmio_reads=len(self.reads), completed=self.result()[3],
                            observed_control_words=list(self.result()[8:20]),
                            result_sha256=hashlib.sha256(struct.pack('<276I', *self.result())).hexdigest()))


class CompiledCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if EXE is None:
            cls.temporary=tempfile.TemporaryDirectory(prefix='xlle-noise-pair-')
            compile_model(Path(cls.temporary.name))

    @classmethod
    def tearDownClass(cls):
        global EXE
        if hasattr(cls,'temporary'):
            cls.temporary.cleanup()
            EXE=None

    def test_real_producer_four_ordered_copies_and_reentry(self):
        m = Machine()
        self.assertEqual(m.call('noise_pair_capture'), 0)
        result = m.result()
        self.assertEqual(result[:8], (0x4e504331,1,0,4,0x01300000,2560,0x01000000,0x01001000))
        self.assertEqual(result[8:20], (0,0,0,1,1,1,1,1,1,0,0,0))
        self.assertEqual(result[20:], tuple(p for row in m.expected_pixels for p in row))
        self.assertEqual(bytes(m.uc.mem_read(0x81000000, 8)), bytes.fromhex('71b50020e4e4e4e4'))
        self.assertEqual(bytes(m.uc.mem_read(0x81000008, 4088)), b'\xa5'*4088)
        self.assertEqual(bytes(m.uc.mem_read(0x81001400, 3072)), b'\xcc'*3072)
        for row in range(8):
            self.assertEqual(bytes(m.uc.mem_read(0x81300000+row*2560+32,2528)),
                             struct.pack('<I',0xcafebabe)*632)
        self.assertEqual(bytes(m.uc.mem_read(0x81300000+8*2560, (480-8)*2560)),
                         struct.pack('<I',0xcafebabe)*((480-8)*640))
        self.assertEqual(bytes(m.uc.mem_read(0x80000000+m.cursor,0x01240000-m.cursor)),
                         b'\x5a'*(0x01240000-m.cursor))
        self.assertEqual((len(m.jobs),m.draws,m.copies), (9,4,4))
        before = (len(m.writes),len(m.reads),m.result())
        self.assertEqual(m.call('noise_pair_capture'),30)
        self.assertEqual((len(m.writes),len(m.reads),m.result()),before)
        m.record(self._testMethodName, 0)

    def test_unpublished_or_invalid_owner_and_resource_failure(self):
        for fault, expected, allocations, locks in [(5,1,0,0),(4,5,0,0),
                (1,31,1,0),(2,32,2,1),(3,31,1,0),(6,10,2,2),
                (7,31,1,1),(8,32,2,2)]:
            with self.subTest(fault=fault):
                m=Machine(fault)
                status=m.call('noise_pair_capture')
                self.assertEqual(status,expected)
                self.assertEqual(m.writes,[])
                self.assertEqual(m.word(m.symbols['model_allocations']),allocations)
                self.assertEqual(m.word(m.symbols['model_locks']),locks)
                self.assertEqual(m.result()[3],0)
                m.record(f'owner/resource-{fault}',status)

    def test_unexpected_write_stops_before_following_operation(self):
        for fault, expected, last in [('index',7,INDEX),('data',8,INDEX),
                ('write-increment',9,DATA),('reselect',7,INDEX),
                ('cache-bits',18,CACHE),('put',14,PUT)]:
            with self.subTest(fault=fault):
                m=Machine(hardware_fault=fault)
                status=m.call('noise_pair_capture')
                self.assertEqual(status,expected)
                self.assertEqual(m.writes[-1][0],last)
                self.assertEqual(m.result()[3],0)
                if fault=='index':
                    self.assertEqual(m.reads[-1],INDEX)
                if fault=='data':
                    self.assertEqual(m.reads[-1],DATA)
                if fault in ('write-increment','reselect'):
                    self.assertEqual(m.reads[-1],INDEX)
                before=(len(m.writes),len(m.reads),m.result())
                self.assertEqual(m.call('noise_pair_capture'),expected)
                self.assertEqual((len(m.writes),len(m.reads),m.result()),before)
                m.record(f'unexpected-{fault}',status)

    def test_finite_timeout_and_gpu_failure_do_not_publish_completion(self):
        for fault, expected, last in [('cache-busy',13,CACHE),('get-stuck',17,PUT),
                ('gpu-error',15,PUT)]:
            with self.subTest(fault=fault):
                m=Machine(hardware_fault=fault)
                status=m.call('noise_pair_capture')
                self.assertEqual(status,expected)
                self.assertEqual(m.writes[-1][0],last)
                self.assertEqual(m.result()[3],0)
                self.assertLess(len(m.reads),65550)
                m.record(f'finite-{fault}',status)


def compile_model(output):
    global EXE
    output.mkdir(parents=True,exist_ok=True)
    # Retain the exact compiled source, including authored helper and input mock.
    snapshots=output/'source';snapshots.mkdir(exist_ok=True)
    sources=['src/noise_pair_capture.c','src/noise_pair_pbkit.inc',
             'tests/noise_pair_mock.c','tests/noise_pair_mock.h','tests/test_noise_pair.py']
    for name in sources:
        destination=snapshots/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes((ROOT/name).read_bytes())
    EXE=output/'capture-model.exe'
    gcc=Path('C:/msys64/mingw64/bin/gcc.exe')
    command=[str(gcc),'-m32','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector',
             '-fno-asynchronous-unwind-tables','-DNOISE_PAIR_MODEL','-nostdlib',
             '-Wl,--entry,_noise_pair_capture','-Wl,--image-base,0x400000',
             '-Wl,--export-all-symbols',str(snapshots/'src/noise_pair_capture.c'),
             str(snapshots/'tests/noise_pair_mock.c'),'-o',str(EXE)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    (output/'compile.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError(result.stderr)
    return command,gcc,snapshots


def main(output):
    command,gcc,snapshots=compile_model(output)
    tests=unittest.defaultTestLoader.loadTestsFromTestCase(CompiledCapture)
    with (output/'tests.log').open('w') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(tests)
    report=dict(scope='Compiled x86 post-bootstrap ownership/control/transport only; model GPU data is not hardware pixels',
                command=command,tests=result.testsRun,success=result.wasSuccessful(),
                cases=RECORDS,network_operations=0,hardware_operations=0,
                artifacts=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                           for p in [gcc,EXE,output/'compile.log',output/'tests.log',*snapshots.rglob('*')]
                           if p.is_file()])
    (output/'compiled-model.aot-private.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(dict(success=report['success'],tests=report['tests'],cases=len(RECORDS),output=str(output))))
    return 0 if report['success'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    raise SystemExit(main(parser.parse_args().output))
