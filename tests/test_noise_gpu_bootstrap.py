"""Execute the actual target-linked initializer under independent kernel/MMIO.

No substituted pb_init, installer, ready setter, pixel generator or live runner.
Positive bootstrap prefix deliberately stops BEFORE its first unsupported write.
The model proves bounded owner/order/retention, not silicon reset or capture.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_EFLAGS

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'))
from noise_gpu_bootstrap_build import build,digest,SDK,PRIMARY

OUTPUT=None
IMAGE=None
RECORDS=[]
RETURN=0x7000f000
STACK=0x82000000
THREAD=0x83000000
NS='{http://nouveau.freedesktop.org/}'
# Independent declarative primary register widths, not the C guard's switch.
VGA_BYTES=set()
vga=ET.parse(PRIMARY/'rnndb/display/nv_vga.xml')
for group,base in [('nv_vga_vio',0xfd0c0000),('nv_vga_cio',0xfd601000),('nv_vga_dio',0xfd681000)]:
    node=vga.find(f'.//{NS}group[@name="{group}"]')
    for register in node.findall(NS+'reg8'):VGA_BYTES.add(base+int(register.attrib['offset'],0))
WIDTH_CASES={
    'width-read-byte':('load_i8',0xfd001804,13),
    'width-read-half':('load_i16',0xfd001804,13),
    'width-write-byte':('store_i8',0xfd001804,13),
    'width-write-half':('store_i16',0xfd001804,13),
    'width-vga-half':('load_i16',0xfd6013d4,13),
    'width-near-vga':('load_i8',0xfd6013d6,13),
    'width-vio-byte':('load_i8',0xfd0c03cc,14),
    'width-cio-byte':('load_i8',0xfd6013d5,14),
    'width-dio-byte':('load_i8',0xfd6813c9,14),
    'width-vga-write':('store_i8',0xfd6013d5,14),
}
class Bar0WidthError(AssertionError):pass

class HashSelection:
    """Passive register configuration only; never a RAMIN/lookup producer.

    Decode the primary field definitions independently of the C masks. Unknown
    fields retain sentinels and remain observable; their effect is not modeled.
    """
    def __init__(self):
        register=ET.parse(PRIMARY/'rnndb/fifo/nv4_pfifo.xml').find(f'.//{NS}reg32[@name="RAMHT"]')
        self.fields={field.attrib['name']:field for field in register.findall(NS+'bitfield')
                     if field.attrib['name'] in ['ADDRESS','SIZE','SEARCH']}
        self.value=0x02020180 # Existing base 18000, 16K table, search 64
        self.publications=[]

    def mask(self,name):
        field=self.fields[name];lo=int(field.attrib['low']);hi=int(field.attrib['high'])
        return ((1<<(hi-lo+1))-1)<<lo

    def decode(self):
        decoded={}
        for name,field in self.fields.items():
            raw=(self.value&self.mask(name))>>int(field.attrib['low'])
            if name=='ADDRESS':decoded[name]=raw<<int(field.attrib['shr'])
            else:decoded[name]=int(next(v.attrib['name'].rstrip('K') for v in field.findall(NS+'value')
                                       if int(v.attrib['value'],0)==raw))*(1024 if name=='SIZE' else 1)
        return decoded

    def publish(self,value,fault):
        known=sum(self.mask(name) for name in self.fields)
        assert value&~known==self.value&~known
        old=self.value;self.value=value
        if fault=='hash-address-readback':self.value=(value&~self.mask('ADDRESS'))|(old&self.mask('ADDRESS'))
        if fault=='hash-size-readback':self.value=(value&~self.mask('SIZE'))|(old&self.mask('SIZE'))
        if fault=='hash-search-readback':self.value=(value&~self.mask('SEARCH'))|(old&self.mask('SEARCH'))
        if fault=='hash-unknown-readback':self.value^=1<<30
        self.publications.append(dict(before=old,requested=value,observed=self.value,decoded=self.decode()))

class Timer:
    """Independent nominal elapsed producer, not reads/polls as completion.

    ACPI ticks inject elapsed time. Rational GPU clocks drive the actual 56-bit
    counter and compare; passive reads cannot create elapsed time or an IRQ.
    This proves documented software ordering, not silicon phase.
    """
    def __init__(self):
        self.div=0xbeef0010;self.mul=0xcafe0003
        self.count=0;self.remainder=0;self.alarm=0;self.armed=False
        self.pending=0;self.mask=0;self.elapsed=0

    def advance(self,acpi_ticks):
        self.elapsed+=acpi_ticks
        div=self.div&0xffff;mul=self.mul&0xffff
        assert div and mul<=div
        ticks,self.remainder=divmod(self.remainder+acpi_ticks*233333324*mul,3375000*div)
        old=self.count;self.count=(self.count+ticks)&((1<<56)-1)
        if self.armed:
            distance=((self.alarm>>5)-(old&((1<<27)-1)))&((1<<27)-1)
            if distance==0 or ticks>=distance:self.pending=1

    def read(self,address):
        return {0xfd009200:self.div,0xfd009210:self.mul,
                0xfd009400:(self.count<<5)&0xffffffff,
                0xfd009410:self.count>>27,0xfd009420:self.alarm,
                0xfd009100:self.pending,0xfd009140:self.mask}[address]

    def write(self,address,value):
        if address==0xfd009200:self.div=value
        elif address==0xfd009210:self.mul=value
        elif address==0xfd009420:
            self.alarm=value&~31;self.armed=True
            if ((self.count<<5)&0xffffffff)==self.alarm:self.pending=1
        elif address==0xfd009140:self.mask=value&1
        elif address==0xfd009100:self.pending&=~(value&1) # Primary W1C, never exercised by owner
        else:raise AssertionError('unknown timer producer')
        # Fractional converter phase after changing its ratio is not established
        # here: nominal fixture restarts the fraction, never claims silicon phase.
        if address in [0xfd009200,0xfd009210]:self.remainder=0

def words(data):return list(struct.unpack('<'+'I'*(len(data)//4),bytes(data)))

class Machine:
    def __init__(self,fault='',image=None):
        self.fault=fault;self.uc=Uc(UC_ARCH_X86,UC_MODE_32)
        self.image=Path(image or IMAGE)
        pe=pefile.PE(str(self.image/'noise-diagnostic.exe'))
        self.base=pe.OPTIONAL_HEADER.ImageBase
        self.uc.mem_map(self.base,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095)
        self.uc.mem_write(self.base,pe.get_memory_mapped_image())
        self.exports={entry.name.decode():self.base+entry.address
                      for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols if entry.name}
        self.symbols={}
        for line in (self.image/'noise-diagnostic.map').read_text().splitlines():
            match=re.match(r' \w{4}:\w{8}\s+(\S+)\s+(\w{16})',line)
            if match:self.symbols[match[1]]=int(match[2],16)
        self.uc.mem_map(0x70000000,0x10000)
        self.uc.mem_map(STACK,0x20000)
        self.uc.mem_map(THREAD,0x2000)
        self.uc.mem_map(0x80000000,0x1000)
        self.uc.mem_map(0xfd000000,0x1000000)
        self.set(THREAD+28,STACK+0x10000);self.set(THREAD+32,STACK)
        self.pci_command=0xf9000003 # STATUS W1C ones must receive zero, not RMW bits
        # Independent PCI fields: a nonzero ROM address, nonzero cache/latency,
        # read-only multifunction/header and BIST-capable/completion sentinels.
        self.pci_rom=0xf0000001
        self.pci_misc=0x87803410
        if fault=='rom-disabled':self.pci_rom&=~1
        if fault=='pci-header':self.pci_misc|=0x00010000
        if fault=='pci-bist':self.pci_misc|=0x40000000
        self.command_reads=0;self.rom_reads=0;self.misc_reads=0
        # Preserve unresolved/variant fields as observed, without treating them
        # as inert: any changed readback is fatal. Only PFIFO transitions here.
        self.engine_enable=0xa5113001
        if fault in ['engine-fifo-enabled','engine-fifo-pending']:self.engine_enable|=0x100
        disabled={'engine-graph-disabled':12,'engine-timer-disabled':16,
                  'engine-fb-disabled':20,'engine-crtc-disabled':24}
        if fault in disabled:self.engine_enable&=~(1<<disabled[fault])
        self.engine_reads=0;self.engine_changes=[];self.engine_written=False
        self.timer=Timer();self.timer_writes=[];self.timer_reads={}
        if fault=='timer-zero-div':self.timer.div&=~0xffff
        if fault=='timer-invalid-ratio':self.timer.mul=(self.timer.mul&~0xffff)|17
        if fault=='timer-intermediate-ratio':self.timer.div=60000;self.timer.mul=58000
        if fault=='timer-stopped':self.timer.mul&=~0xffff
        if fault=='timer-alarm-pending':self.timer.pending=1
        self.instance=None
        self.hash=HashSelection();self.hash_reads=0;self.hash_mask_written=False
        if fault=='hash-unknown-retained':self.hash.value|=0x40000004
        # Actual empty/disabled consumers, rather than a caller ready flag.
        for address in [0xfd002400,0xfd003014,0xfd003214]:self.set(address,0x10)
        fifo_faults={'hash-reassign':(0xfd002500,1),'hash-cache-access':(0xfd003000,1),
                     'hash-hash-busy':(0xfd003250,0x1000),'hash-dma-busy':(0xfd003220,0x10),
                     'hash-cache-not-empty':(0xfd003014,0),'hash-runout-pending':(0xfd002410,4),
                     'hash-acquire-busy':(0xfd003250,0x10000),
                     'hash-acquire-active':(0xfd003254,0x10)}
        if fault in fifo_faults:self.set(*fifo_faults[fault])
        self.set(0xfd680500,0x00011c01) # Actual SDK M=1,N=28,P=1 -> 233333324 Hz
        if fault=='pll-zero':self.set(0xfd680500,0)
        if fault=='pll-rate':self.set(0xfd680500,0x00011b01)
        self.kernel={}
        defs=(SDK/'lib/xboxkrnl/xboxkrnl.exe.def').read_text()
        for name,arg_bytes,ordinal in re.findall(r'^\s+(\w+)(?:@(\d+))?\s+@\s*(\d+) NONAME',defs,re.M):
            self.kernel[int(ordinal)]=(name,int(arg_bytes or 0))
        for directory in pe.DIRECTORY_ENTRY_IMPORT:
            if directory.dll.lower()!=b'xboxkrnl.exe':raise AssertionError('unexpected foreign provider')
            for entry in directory.imports:
                self.set(entry.address,0x70000000+entry.ordinal*16)
        pe.close()
        self.clock=100;self.kernel_calls=[];self.mmio=[];self.allocations=[];self.pins=[]
        self.counter_calls=0;self.interrupt=None;self.connected=False
        self.inject=False;self.injected=False;self.pending_import=False
        self.width_pending=False;self.width_injected=False;self.width_violation=None
        self.next_ram=0x80100000
        self.uc.hook_add(UC_HOOK_CODE,self.provider,begin=0x70000000,end=0x70003000)
        poll=self.symbols['_noise_boot_poll']
        self.uc.hook_add(UC_HOOK_CODE,self.poll_hook,begin=poll,end=poll)
        self.uc.hook_add(UC_HOOK_MEM_READ,self.mmio_read,begin=0xfd000000,end=0xfdffffff)
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.mmio_write,begin=0xfd000000,end=0xfdffffff)
        if fault=='irq-after-hash':
            boundary=self.symbols['_noise_idle_fifo']
            self.uc.hook_add(UC_HOOK_CODE,self.foreground_irq_hook,begin=boundary,end=boundary)
        entry=self.symbols['_noise_boot_bus_master']
        self.uc.hook_add(UC_HOOK_CODE,self.width_hook,begin=entry,end=entry)

    def set(self,address,value):self.uc.mem_write(address,struct.pack('<I',value&0xffffffff))
    def get(self,address):return words(self.uc.mem_read(address,4))[0]
    def result(self):return words(self.uc.mem_read(self.exports['noise_gpu_bootstrap_result'],(24+48)*4))
    def allocation(self,address):
        return next((a for a in self.allocations if a['address']<=address<a['address']+a['size']),None)

    def provider(self,uc,address,size,data):
        ordinal=(address-0x70000000)//16
        name,arg_bytes=self.kernel[ordinal]
        stack=uc.reg_read(UC_X86_REG_ESP)
        arguments=words(uc.mem_read(stack+4,arg_bytes)) if arg_bytes else []
        self.kernel_calls.append([name,arguments])
        value=0
        if name=='KeQueryPerformanceFrequency':
            value=0 if self.fault=='frequency' else 1000000 if self.fault=='wrong-frequency' else 3375000
        elif name=='KeQueryPerformanceCounter':
            self.counter_calls+=1
            previous=self.clock
            if self.fault=='counter-stuck':pass
            elif self.fault=='counter-backward' and self.counter_calls==2:self.clock-=1
            elif self.fault=='elapsed' and self.counter_calls>4:self.clock+=10000000
            else:self.clock+=10
            value=self.clock
            if self.fault not in ['timer-zero-div','timer-invalid-ratio']:
                self.timer.advance(max(0,self.clock-previous))
        elif name=='KeGetCurrentThread':value=0 if self.fault=='stack' else THREAD
        elif name=='MmIsAddressValid':
            address=arguments[0];value=int(address in [0x80000000,STACK,STACK+0xffff] or
                THREAD<=address<THREAD+0x1000 or self.allocation(address) is not None or
                self.instance and self.instance['start']<=address<self.instance['top'])
            if self.fault=='zero-page' and address==0x80000000:value=0
        elif name=='MmGetPhysicalAddress':
            address=arguments[0];allocation=self.allocation(address)
            value=address-0x80000000
            if allocation:value=allocation['physical']+address-allocation['address']
            if self.fault=='noncontiguous' and allocation and address!=allocation['address']:value^=0x1000
        elif name=='MmQueryAddressProtect':
            allocation=self.allocation(arguments[0]);value=allocation['protect'] if allocation else 4
            if allocation and self.fault=='protection':value=2
            if allocation and self.fault=='post-pin' and self.pins:value=2
            if self.instance and self.instance['start']<=arguments[0]<self.instance['top']:
                if self.fault=='instance-protection' or (self.fault=='instance-post-pin' and len(self.pins)==5):value=2
        elif name=='MmQueryAllocationSize':
            allocation=self.allocation(arguments[0]);assert allocation
            value=allocation['size']-(4096 if self.fault=='allocation-size' else 0)
        elif name=='HalGetInterruptVector':
            assert arguments[0]==3
            self.uc.mem_write(arguments[1],b'\x04');value=0x33
        elif name=='KeInitializeInterrupt':
            obj,routine,context,vector,irql,mode,shared=arguments
            assert context==0 and vector==0x33 and irql==4 and mode==0 and shared==0
            self.interrupt=(obj,routine)
        elif name=='KeConnectInterrupt':
            assert self.interrupt and arguments==[self.interrupt[0]]
            if self.fault in ['irq-in-connect','concurrent-bootstrap'] and not self.injected:
                self.inject=True;self.pending_import=True;uc.emu_stop();return
            value=int(self.fault!='irq-busy');self.connected=bool(value)
        elif name=='MmAllocateContiguousMemoryEx':
            assert self.connected
            count,low,high,align,protect=arguments
            assert low==4096 and high==0x03ffafff and align in [4096,16384]
            if self.fault=='allocation-failure' and len(self.allocations)==1:value=0
            else:
                address=(self.next_ram+align-1)&~(align-1)
                physical=address-0x80000000
                if self.fault=='allocation-high':physical=0x03ffb000
                if self.fault=='allocation-zero':physical=0
                if self.fault=='overlap' and self.allocations:physical=self.allocations[0]['physical']
                uc.mem_map(address,count);uc.mem_write(address,b'\xa5'*count)
                self.allocations.append(dict(address=address,size=count,physical=physical,protect=protect))
                self.next_ram=address+count+4096;value=address
                if self.fault=='irq-during-allocation':self.inject=True
        elif name=='MmLockUnlockBufferPages':
            assert arguments[2]==0
            self.pins.append(arguments[:2])
        elif name=='MmClaimGpuInstanceMemory':
            assert arguments[0]==0xffffffff and self.instance is None
            if self.fault=='instance-failure':value=0
            else:
                top=0x83ff0000;start=top-0x5000
                self.uc.mem_map(start,0x5000);self.uc.mem_write(start,b'\x5a'*0x5000)
                self.instance=dict(top=top,start=start,physical=start-0x80000000,padding=0x10000)
                self.set(arguments[1],0x10000 if self.fault!='instance-padding' else 0x4000)
                value=top
        elif name=='NtCreateEvent':
            assert arguments[1:]==[0,0,0]
            self.set(arguments[0],0x1234);value=0xc000009a if self.fault=='event' else 0
        else:raise AssertionError(f'undeclared kernel operation {name}: {arguments}')
        uc.reg_write(UC_X86_REG_EAX,value&0xffffffff)
        uc.reg_write(UC_X86_REG_EDX,(value>>32)&0xffffffff)
        uc.reg_write(UC_X86_REG_ESP,stack+4+arg_bytes)
        uc.reg_write(UC_X86_REG_EIP,self.get(stack))
        if self.inject and not self.injected and self.fault=='irq-during-allocation':uc.emu_stop()

    def mmio_read(self,uc,access,address,size,value,data):
        self.check_primary_width('read',address,size)
        if address==0xfd000200:
            self.engine_reads+=1
            if self.fault=='engine-drift' and self.engine_reads==4:self.engine_enable^=0x20000000
            self.set(address,self.engine_enable)
        if address in [0xfd009140,0xfd009200,0xfd009210,0xfd009420,0xfd009100,0xfd009400,0xfd009410]:
            self.timer_reads[address]=self.timer_reads.get(address,0)+1
            if self.fault=='timer-drift' and address==0xfd009200 and self.timer_reads[address]==2:
                self.timer.div^=1
            if self.fault=='timer-mask-drift' and address==0xfd009140 and any(w[0]==0xfd009200 for w in self.timer_writes):self.timer.mask=1
            if self.fault=='timer-status' and address==0xfd009100:self.timer.pending=2
            self.set(address,self.timer.read(address))
        if address==0xfd100200:self.set(address,3 if self.fault!='framebuffer-config' else 0)
        if address==0xfd000100 and self.fault=='engine-pending' and self.engine_reads>=4:self.set(address,0x100)
        if address==0xfd002100:
            assert self.engine_enable&0x100 # No disabled-engine MMIO assumption
            if self.fault=='engine-fifo-pending' or (self.fault=='engine-output-pending' and self.engine_written):
                self.set(address,1)
        if address in [0xfd400700,0xfd400108]:assert self.engine_enable&0x1000
        if address in [0xfd600140]:assert self.engine_enable&0x1000000
        if address in [0xfd009140,0xfd009200,0xfd009210,0xfd009420]:assert self.engine_enable&0x10000
        if address==0xfd400700 and self.fault=='busy':self.set(address,1)
        if address==0xfd000140 and self.fault=='mask-readback' and any(x[0]=='write' for x in self.mmio):self.set(address,1)
        if address==0xfd600140 and self.fault=='crtc-readback':self.set(address,1)
        if address==0xfd000140 and self.fault=='irq-in-connect' and self.injected:self.set(address,1)
        if address==0xfd000140 and self.fault=='irq-after-command' and self.injected:self.set(address,1)
        if address==0xfd000140 and self.fault=='irq-during-allocation' and self.injected:self.set(address,1)
        if address==0xfd000140 and self.fault=='irq-after-timer' and self.injected:self.set(address,1)
        if address==0xfd000140 and self.fault=='irq-after-hash' and self.injected:self.set(address,1)
        if address==0xfd000140 and self.fault=='hash-mask-readback' and self.hash_mask_written:self.set(address,1)
        if address==0xfd002210:
            assert self.engine_enable&0x100
            self.hash_reads+=1
            if self.fault=='hash-context-drift' and self.hash_reads==2:self.hash.value^=0x10
            self.set(address,self.hash.value)
        if address==0xfd001804:
            self.command_reads+=1
            if self.fault=='command-drift' and self.command_reads==2:self.pci_command^=2
            self.set(address,self.pci_command)
        if address==0xfd001830:
            self.rom_reads+=1
            if self.fault=='rom-drift' and self.rom_reads==2:self.pci_rom^=0x800
            self.set(address,self.pci_rom)
        if address==0xfd00180c:
            self.misc_reads+=1
            if self.fault=='misc-drift' and self.misc_reads==2:self.pci_misc|=0x40000000
            self.set(address,self.pci_misc)
        self.mmio.append(['read',address,size,int.from_bytes(uc.mem_read(address,size),'little')])

    def mmio_write(self,uc,access,address,size,value,data):
        self.check_primary_width('write',address,size)
        assert self.connected or (self.pending_import and self.injected)
        self.mmio.append(['write',address,size,value])
        if address==0xfd001804:
            assert size==4 and value==7
            # Ordinary command bits and W1C status are distinct hardware effects.
            if self.fault!='command-readback':
                self.pci_command=(self.pci_command&0xffff0000&~(value&0xf9000000))|(value&0xffff)
            if self.fault in ['irq-after-command','irq-pending']:self.inject=True
        elif address==0xfd001830:
            assert size==4 and value==(self.pci_rom&~1)
            if self.fault!='rom-readback':self.pci_rom=value
            if self.fault=='rom-address-readback':self.pci_rom^=0x800
        elif address==0xfd00180c:
            assert size==4 and value==((self.pci_misc&~0xffff)|0xf800)
            # Header, multifunction, BIST capability/result are read-only here;
            # BIST START is writable but the real preflight requires it clear.
            writable=0x4000ffff
            if self.fault=='cache-readback':writable&=~0xff
            if self.fault=='latency-readback':writable&=~0xff00
            self.pci_misc=(self.pci_misc&~writable)|(value&writable)
        elif address==0xfd000200:
            before=self.engine_enable
            assert (before^value)&~0x1100==0 and value&0x1100==0x1100
            assert before&0x01111000==0x01111000
            self.engine_changes.append(dict(before=before,requested=value,changed=before^value))
            self.engine_written=True
            if self.fault!='engine-readback':self.engine_enable=value
            if self.fault=='engine-unknown-readback':self.engine_enable^=0x20000000
        elif address==0xfd000140 and value==0 and self.instance:
            self.hash_mask_written=True
            if self.fault=='hash-recheck-busy':self.set(0xfd003220,0x10)
        elif address==0xfd002210:
            assert self.get(0xfd000140)==0
            self.hash.publish(value,self.fault)
            assert self.hash.publications[-1]['decoded']==dict(ADDRESS=0x10000,SIZE=4096,SEARCH=128) or self.fault.endswith('readback')
            if self.fault=='hash-output-pending':self.set(0xfd002100,1)
            if self.fault=='irq-after-hash':self.inject=True
        elif address in [0xfd009140,0xfd009200,0xfd009210,0xfd009420,0xfd009100]:
            self.timer_writes.append([address,value])
            fault={0xfd009200:'timer-div-readback',0xfd009210:'timer-mul-readback',
                   0xfd009420:'timer-alarm-readback'}.get(address)
            if self.fault!=fault:self.timer.write(address,value)
            if self.fault=='timer-upper-readback' and address==0xfd009200:self.timer.div^=0x10000000
            if self.fault=='timer-alarm-low-readback' and address==0xfd009420:self.timer.alarm|=1
            if self.fault=='irq-after-timer' and address==0xfd009200:self.inject=True

    def check_primary_width(self,operation,address,size):
        valid=(size==1 and address in VGA_BYTES) or (size==4 and not(address&3) and
            not any(address+i in VGA_BYTES for i in range(4)))
        if not valid:
            self.width_violation=dict(operation=operation,address=address,bytes=size)
            raise Bar0WidthError(f'unsupported BAR0 {operation}: {address:08x}/{size}')

    def width_hook(self,uc,address,size,data):
        if self.fault in WIDTH_CASES and not self.width_injected:
            self.width_pending=True;uc.emu_stop()

    def poll_hook(self,uc,address,size,data):
        if self.inject and not self.injected and (uc.reg_read(UC_X86_REG_EFLAGS)&0x200):
            uc.emu_stop()

    def foreground_irq_hook(self,uc,address,size,data):
        # Deliver at the actual post-check entry if CPU interrupts are exposed.
        # The corrected owner keeps IF clear here; normal delivery then occurs
        # at the following real poll. This catches unguarded post-check reads.
        if self.inject and not self.injected and (uc.reg_read(UC_X86_REG_EFLAGS)&0x200):uc.emu_stop()

    def drive(self,address):
        for _ in range(4):
            self.uc.emu_start(address,RETURN,count=15000000)
            if self.width_pending:
                # A negative/representative API invocation in the real active
                # command, after its actual allocator/event/IRQ producers.
                # This does not replace SDK setup, advance its PC or set ready.
                self.width_pending=False;self.width_injected=True
                context=self.uc.context_save()
                kind,target,_=WIDTH_CASES[self.fault]
                self.set(target,0x5a)
                stack=STACK+0xe000
                self.uc.mem_write(stack,struct.pack('<III',RETURN,target,7))
                self.uc.reg_write(UC_X86_REG_ESP,stack)
                function=self.symbols['_noise_boot_'+kind]
                self.uc.emu_start(function,RETURN,count=100000)
                assert self.uc.reg_read(UC_X86_REG_EIP)==RETURN
                if self.result()[2]:return self.uc.reg_read(UC_X86_REG_EAX)
                assert kind=='load_i8' and target in VGA_BYTES
                assert self.uc.reg_read(UC_X86_REG_EAX)==0x5a
                self.uc.context_restore(context)
                address=self.uc.reg_read(UC_X86_REG_EIP);continue
            if self.inject and not self.injected:
                self.injected=True
                context=self.uc.context_save()
                irq_stack=STACK+0x1f000
                reentry=self.fault=='concurrent-bootstrap'
                if not reentry:self.set(0xfd000100,0x1000)
                target=self.exports['noise_gpu_bootstrap'] if reentry else self.interrupt[1]
                before=(len(self.mmio),len(self.kernel_calls))
                self.uc.mem_write(irq_stack,struct.pack('<III',RETURN,self.interrupt[0],0))
                self.uc.reg_write(UC_X86_REG_ESP,irq_stack)
                self.uc.reg_write(UC_X86_REG_EIP,target)
                self.uc.emu_start(target,RETURN,count=100000)
                assert self.uc.reg_read(UC_X86_REG_EIP)==RETURN
                if reentry:
                    assert self.uc.reg_read(UC_X86_REG_EAX)==28
                    assert before==(len(self.mmio),len(self.kernel_calls))
                self.uc.context_restore(context)
                address=self.uc.reg_read(UC_X86_REG_EIP);continue
            if self.uc.reg_read(UC_X86_REG_EIP)!=RETURN:raise AssertionError('finite instruction ceiling exceeded')
            return self.uc.reg_read(UC_X86_REG_EAX)
        raise AssertionError('unexpected repeated interrupt dispatch')

    def call(self,name):
        stack=STACK+0xf000
        self.set(stack,RETURN);self.uc.reg_write(UC_X86_REG_ESP,stack)
        self.uc.reg_write(UC_X86_REG_EFLAGS,0x202)
        return self.drive(self.exports[name])

class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global IMAGE
        if OUTPUT:
            IMAGE=OUTPUT/'image';IMAGE.mkdir(parents=True,exist_ok=True)
        else:
            cls.temporary=tempfile.TemporaryDirectory(prefix='noise-bootstrap-')
            IMAGE=Path(cls.temporary.name)/'image'
        build(IMAGE,xbe=bool(OUTPUT))
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'temporary'):cls.temporary.cleanup()

    def check(self,fault,status,retained=None,writes=None):
        machine=Machine(fault);result=machine.call('noise_gpu_bootstrap')
        self.assertEqual(result,status,fault)
        state=machine.result();self.assertEqual(state[2],status)
        finished_flags=machine.uc.reg_read(UC_X86_REG_EFLAGS)
        self.assertTrue(finished_flags&0x200,'foreground guard must restore original CPU interrupt flag')
        if retained is not None:self.assertEqual(state[7],retained)
        stores=[x for x in machine.mmio if x[0]=='write']
        if writes is not None:self.assertEqual(len(stores),writes)
        before=(len(machine.mmio),len(machine.kernel_calls))
        self.assertEqual(machine.call('noise_gpu_bootstrap'),status)
        self.assertEqual(machine.call('noise_gpu_capture'),26)
        self.assertEqual((len(machine.mmio),len(machine.kernel_calls)),before)
        self.assertFalse(any(x[0] in ['MmFreeContiguousMemory','KeDisconnectInterrupt','NtClose',
                                    'KeInsertQueueDpc','KeRemoveQueueDpc','HalRegisterShutdownNotification']
                             for x in machine.kernel_calls))
        RECORDS.append(dict(fault=fault or 'none',status=status,result=state,
                            mmio=machine.mmio,kernel_calls=machine.kernel_calls,
                            pins=machine.pins,allocations=machine.allocations,
                            engine_changes=machine.engine_changes,timer_writes=machine.timer_writes,
                            hash_publications=machine.hash.publications,finished_cpu_flags=finished_flags,
                            timer=dict(elapsed_acpi_ticks=machine.timer.elapsed,counter=machine.timer.count,
                                       pending=machine.timer.pending,mask=machine.timer.mask),instance=machine.instance))
        return machine

    def test_genuine_sdk_prefix_and_guard(self):
        machine=self.check('',14,4,13)
        state=machine.result()
        self.assertEqual(state[8:10],[0xfd002214,0x00890110])
        self.assertEqual(state[22:24],[0,0]) # unsupported store and readback NOT performed
        self.assertEqual(machine.get(0xfd001804),0xf9000007)
        self.assertEqual(len(machine.pins),5)
        for allocation in machine.allocations:
            self.assertEqual(machine.uc.mem_read(allocation['address'],32),b'\0'*32)
        self.assertEqual(machine.get(0xfd001830),0xf0000000) # never clears/moves the address
        self.assertEqual(machine.get(0xfd00180c),0x8780f800) # no header/BIST write
        stores=[x for x in machine.mmio if x[0]=='write']
        self.assertEqual(stores[-5:],[['write',0xfd009200,4,0xbeefde88],
                                    ['write',0xfd009210,4,0xcafe1dcd],
                                    ['write',0xfd009420,4,0xffffffff],
                                    ['write',0xfd000140,4,0],
                                    ['write',0xfd002210,4,0x03000100]])
        self.assertTrue(all(x[2]==4 for x in stores))
        self.assertEqual(machine.engine_changes,[dict(before=0xa5113001,requested=0xa5113101,changed=0x100)])
        self.assertEqual([x for x in machine.mmio if x[1]==0xfd680500],
                         [['read',0xfd680500,4,0x11c01]]*7)
        self.assertFalse(any(x[1]==0xfd002214 or x[1]>=0xfd700000 for x in machine.mmio))
        self.assertEqual(machine.instance,dict(top=0x83ff0000,start=0x83feb000,physical=0x03feb000,padding=0x10000))
        self.assertEqual(machine.pins[-1],[0x83feb000,0x5000])
        self.assertEqual(machine.uc.mem_read(0x83feb000,0x5000),b'\x5a'*0x5000) # No guessed PRAMIN alias/store
        self.assertEqual(state[13],0) # no fabricated successful SDK return
        self.assertEqual(state[15],0) # original ready producer has not been reached

    def test_preflight_and_exclusive_owner(self):
        for fault,status in [('frequency',6),('counter-stuck',7),('counter-backward',7),
                             ('stack',4),('zero-page',22),('busy',9),('irq-busy',11)]:
            with self.subTest(fault=fault):self.check(fault,status,0,0)
        self.check('mask-readback',12,0,1)
        self.check('concurrent-bootstrap',14,4,13)

    def test_pci_effect_readback_and_ownership(self):
        machine=self.check('command-readback',12,4,2)
        self.assertEqual(machine.mmio[-2:],[['write',0xfd001804,4,7],
                                         ['read',0xfd001804,4,0xf9000003]])
        machine=self.check('command-drift',14,4,1)
        self.assertEqual(machine.result()[8:10],[0xfd001804,7])
        self.assertEqual(machine.result()[22:24],[0,0])
        self.assertFalse(any(x[0]=='write' and x[1]==0xfd001804 for x in machine.mmio))
        machine=self.check('rom-disabled',14,4,13)
        self.assertEqual(machine.get(0xfd001830),0xf0000000)
        for fault in ['pci-header','pci-bist']:
            with self.subTest(fault=fault):
                machine=self.check(fault,31,4,4)
                self.assertEqual(machine.result()[22:24],[0,1])
                self.assertFalse(any(x[1]==0xfd001830 for x in machine.mmio))
        for fault,address,count in [('rom-readback',0xfd001830,5),
                                     ('rom-address-readback',0xfd001830,5),
                                     ('cache-readback',0xfd00180c,6),
                                     ('latency-readback',0xfd00180c,6)]:
            with self.subTest(fault=fault):
                machine=self.check(fault,12,4,count)
                self.assertEqual(machine.mmio[-2][0:2],['write',address])
                self.assertEqual(machine.mmio[-1][0:2],['read',address])
                self.assertEqual(machine.result()[22:24],[1,1])
        machine=self.check('rom-drift',14,4,4)
        self.assertEqual(machine.result()[8:10],[0xfd001830,0xf0000000])
        self.assertEqual(machine.result()[22:24],[0,0])
        self.assertFalse(any(x[0]=='write' and x[1]==0xfd001830 for x in machine.mmio))
        machine=self.check('misc-drift',14,4,5)
        self.assertEqual(machine.result()[8:10],[0xfd00180c,0x8780f800])
        self.assertEqual(machine.result()[22:24],[0,0])
        self.assertFalse(any(x[0]=='write' and x[1]==0xfd00180c for x in machine.mmio))

    def test_owned_memory_and_result_order(self):
        for fault,retained in [('allocation-failure',1),('protection',1),('post-pin',1),
                               ('noncontiguous',1),('allocation-size',1),('allocation-high',1),
                               ('allocation-zero',1),('overlap',2)]:
            with self.subTest(fault=fault):
                self.check(fault,19 if fault=='allocation-failure' else 20,retained,1)
        self.check('event',24,4,1)
        self.check('crtc-readback',12,4,3)
        self.check('elapsed',8)

    def test_primary_bar0_width_guards(self):
        for fault,(kind,address,status) in WIDTH_CASES.items():
            with self.subTest(fault=fault):
                positive=fault in ['width-vio-byte','width-cio-byte','width-dio-byte']
                machine=self.check(fault,status,4,13 if positive else 1)
                self.assertTrue(machine.width_injected)
                self.assertIsNone(machine.width_violation) # guard precedes provider
                if not positive:
                    self.assertEqual(machine.result()[8],address)
                    self.assertEqual(machine.result()[22:24],[0,0])
                    self.assertFalse(any(x[1]==address for x in machine.mmio))
                else:
                    self.assertIn(['read',address,1,0x5a],machine.mmio)

    def test_irq_failure_has_no_following_operation(self):
        for fault in ['irq-in-connect','irq-after-command','irq-during-allocation','irq-after-timer','irq-after-hash']:
            machine=self.check(fault,12)
            self.assertTrue(machine.injected)
            self.assertEqual(machine.mmio[-2:], [['write',0xfd000140,4,0],['read',0xfd000140,4,1]])
            self.assertEqual(machine.result()[17],1)
            self.assertEqual(machine.result()[22:24],[1,1])
            if fault=='irq-during-allocation':
                self.assertEqual(machine.result()[7],1)
                self.assertEqual(machine.kernel_calls[-1][0],'MmAllocateContiguousMemoryEx')
                self.assertEqual(machine.pins,[])
            if fault=='irq-after-timer':
                self.assertFalse(any(x[0]=='write' and x[1] in [0xfd009210,0xfd009420] for x in machine.mmio))
                self.assertIsNone(machine.instance)
            if fault=='irq-after-hash':
                self.assertEqual(len(machine.hash.publications),1)
                self.assertFalse(any(x[1]==0xfd002214 for x in machine.mmio))
        machine=self.check('irq-pending',32,4,7)
        self.assertEqual(machine.result()[6],1)
        self.assertEqual(machine.result()[15],0) # real ready producer not reached

    def test_documented_engine_enable_and_retained_state(self):
        machine=self.check('engine-fifo-enabled',14,4,13)
        self.assertEqual(machine.engine_changes,[dict(before=0xa5113101,requested=0xa5113101,changed=0)])
        for fault in ['engine-graph-disabled','engine-timer-disabled','engine-fb-disabled','engine-crtc-disabled']:
            with self.subTest(fault=fault):
                machine=self.check(fault,32,0,0)
                self.assertEqual(machine.mmio,[['read',0xfd000200,4,machine.engine_enable]])
                self.assertEqual(machine.result()[22:24],[0,1])
        for fault in ['engine-readback','engine-unknown-readback']:
            with self.subTest(fault=fault):
                machine=self.check(fault,12,4,7)
                self.assertEqual(machine.mmio[-2][0:2],['write',0xfd000200])
                self.assertEqual(machine.mmio[-1][0:2],['read',0xfd000200])
                self.assertEqual(machine.result()[22:24],[1,1])
        for fault in ['engine-drift','engine-pending','engine-fifo-pending']:
            with self.subTest(fault=fault):
                machine=self.check(fault,32,4,6)
                self.assertFalse(machine.engine_written)
                self.assertEqual(machine.result()[22:24],[0,0])
        machine=self.check('engine-output-pending',32,4,7)
        self.assertEqual(machine.mmio[-1],['read',0xfd002100,4,1])
        self.assertFalse(any(x[0]=='write' and x[1]==0xfd000140 and x[3]==1 for x in machine.mmio))
        for fault in ['pll-zero','pll-rate']:
            with self.subTest(fault=fault):
                machine=self.check(fault,30,4,8)
                self.assertFalse(any(x[1]==0xfd009200 for x in machine.mmio))

    def test_timer_producer_context_and_instance_owner(self):
        self.check('wrong-frequency',6,0,0)
        for fault in ['timer-zero-div','timer-invalid-ratio','timer-intermediate-ratio']:
            with self.subTest(fault=fault):self.check(fault,33,4,8)
        for fault,address,count in [('timer-div-readback',0xfd009200,9),
                                     ('timer-upper-readback',0xfd009200,9),
                                     ('timer-mul-readback',0xfd009210,10),
                                     ('timer-alarm-readback',0xfd009420,11),
                                     ('timer-alarm-low-readback',0xfd009420,11)]:
            with self.subTest(fault=fault):
                machine=self.check(fault,12,4,count)
                self.assertEqual(machine.mmio[-2][0:2],['write',address])
                self.assertEqual(machine.mmio[-1][0:2],['read',address])
                self.assertIsNone(machine.instance)
        self.check('timer-drift',33,4,8)
        self.check('timer-mask-drift',33,4,9) # Genuine DIV completion precedes context change
        self.check('timer-status',33,4,11)
        for fault in ['timer-stopped','timer-alarm-pending']:
            with self.subTest(fault=fault):
                machine=self.check(fault,14,4,13)
                self.assertEqual(machine.timer.div&0xffff,56968)
                self.assertEqual(machine.timer.mul&0xffff,7629)
                self.assertEqual(machine.timer.alarm,0xffffffe0)
                self.assertEqual(machine.timer.mask,0)
                self.assertFalse(any(x[0]=='write' and x[1]==0xfd009100 for x in machine.mmio))
                if fault=='timer-alarm-pending':self.assertEqual(machine.timer.pending,1)
        self.check('framebuffer-config',30,4,11)
        for fault in ['instance-failure','instance-padding','instance-protection','instance-post-pin']:
            with self.subTest(fault=fault):
                machine=self.check(fault,23,4,11)
                self.assertFalse(any(x[1]>=0xfd700000 for x in machine.mmio))

    def test_idle_hash_selection_and_fail_stop(self):
        machine=self.check('hash-unknown-retained',14,4,13)
        self.assertEqual(machine.hash.value,0x43000104)
        self.assertEqual(machine.hash.decode(),dict(ADDRESS=0x10000,SIZE=4096,SEARCH=128))
        self.assertEqual(len(machine.hash.publications),1)
        self.assertEqual(machine.get(0xfd000140),0)
        for fault in ['hash-reassign','hash-cache-access','hash-hash-busy','hash-dma-busy',
                      'hash-cache-not-empty','hash-runout-pending','hash-acquire-busy','hash-acquire-active']:
            with self.subTest(fault=fault):
                machine=self.check(fault,34,4,11)
                self.assertEqual(machine.hash.publications,[])
                self.assertEqual(machine.get(0xfd000140),1) # no control change on a busy owner
        for fault in ['hash-recheck-busy','hash-context-drift']:
            with self.subTest(fault=fault):
                machine=self.check(fault,34,4,12)
                self.assertEqual(machine.hash.publications,[])
                self.assertEqual(machine.get(0xfd000140),0)
        machine=self.check('hash-mask-readback',12,4,12)
        self.assertEqual(machine.mmio[-2:],[['write',0xfd000140,4,0],['read',0xfd000140,4,1]])
        self.assertEqual(machine.result()[8:11],[0xfd000140,0,1])
        self.assertEqual(machine.hash.publications,[])
        for fault in ['hash-address-readback','hash-size-readback','hash-search-readback','hash-unknown-readback']:
            with self.subTest(fault=fault):
                machine=self.check(fault,12,4,13)
                self.assertEqual(machine.mmio[-2][0:3],['write',0xfd002210,4])
                self.assertEqual(machine.mmio[-1][0:3],['read',0xfd002210,4])
                self.assertEqual(machine.result()[22:24],[1,1])
                self.assertFalse(any(x[1]==0xfd002214 for x in machine.mmio))
        machine=self.check('hash-output-pending',34,4,13)
        self.assertEqual(machine.mmio[-1],['read',0xfd002100,4,1])
        self.assertEqual(len(machine.hash.publications),1)
        self.assertFalse(any(x[1]>=0xfd700000 for x in machine.mmio))

    def test_independent_timer_elapsed_alarm_and_passive_reads(self):
        timer=Timer();timer.write(0xfd009200,56968);timer.write(0xfd009210,7629)
        timer.write(0xfd009420,0xffffffff)
        before=(timer.count,timer.elapsed,timer.pending)
        for _ in range(100):
            self.assertEqual(timer.read(0xfd009420),0xffffffe0)
            timer.read(0xfd009400);timer.read(0xfd009100)
        self.assertEqual((timer.count,timer.elapsed,timer.pending),before)
        timer.advance(15000000)
        expected=15000000*233333324*7629//(3375000*56968)
        self.assertEqual(timer.count,expected)
        self.assertGreater(expected,(1<<27)-1)
        self.assertEqual(timer.pending,1);self.assertEqual(timer.mask,0)
        timer.write(0xfd009100,0);self.assertEqual(timer.pending,1)
        timer.write(0xfd009100,1);self.assertEqual(timer.pending,0)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--prior-image',type=Path,help='Retained pre-fix linked PE directory; offline causal observation only')
    args,remaining=parser.parse_known_args();OUTPUT=args.output
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(BootstrapTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    prior_repro=None
    if args.prior_image:
        machine=Machine(image=args.prior_image)
        try:machine.call('noise_gpu_bootstrap')
        except Bar0WidthError:
            assert machine.width_violation==dict(operation='read',address=0xfd001804,bytes=2)
            prior_repro=dict(scope='Prior halfword-load failure under primary-derived BAR0 model; not a physical failure',
                violation=machine.width_violation,result=machine.result(),mmio=machine.mmio,
                kernel_calls=machine.kernel_calls,
                artifacts=[dict(path=str(args.prior_image/name),sha256=digest(args.prior_image/name))
                           for name in ['noise-diagnostic.exe','noise-diagnostic.map','compiled-bootstrap.aot-private.json']])
        else:raise AssertionError('expected causal pre-fix width failure was not reproduced')
    if OUTPUT:
        artifacts=[dict(path=str(p),sha256=digest(p)) for p in IMAGE.rglob('*') if p.is_file()]
        report=dict(scope='Actual SDK bootstrap prefix and owner/failure proof; no working capture or silicon qualification',
                    groups=result.testsRun,cases=len(RECORDS),success=result.wasSuccessful(),
                    records=RECORDS,artifacts=artifacts,network_operations=0,
                    prior_width_failure=prior_repro,
                    source=dict(path=str(Path(__file__).resolve()),sha256=digest(__file__)))
        (OUTPUT/'compiled-bootstrap-model.aot-private.json').write_text(json.dumps(report,indent=2))
    raise SystemExit(not result.wasSuccessful())
