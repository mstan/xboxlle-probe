# Guarded diagnostic GPU bootstrap

This is an offline, separately linked bootstrap owner and paired-capture XBE.
It advances the required interrupt/resource/stop boundary. It is **not a working
capture**: the actual SDK initializer stops before its first unreviewed register
effect. Enabled DXT1 pixels, full bootstrap and the parent graphics gate remain
open. Nothing here authorizes a console operation.

The stock SDK checkout, default Makefile, resident main and wire protocol remain
unchanged. The distinct image links the unchanged resident agent and its normal
startup, including the existing screen/network initialization. It does not call
the diagnostic bootstrap or capture automatically and adds no network command.
The two explicit no-argument C exports require a separately authorized,
hash-bound invocation through the existing ARM-guarded EXEC mechanism. The
builder reports actual PE and converted XBE addresses and initial byte identity;
it does not upload, launch, connect to a console or generate a live runner.

## Actual owner and finite execution

`noise_gpu_bootstrap` atomically claims a single command lifetime. It verifies an
advancing, bounded-frequency performance counter, the real current thread's
stack interval, quiet PGRAPH/PMC status, and the existing console-reserved page 0
mapping/protection/physical provenance. That page is never allocated or freed.
It then requests the actual IRQ 3 vector, initializes its own interrupt object
with `ShareVector=FALSE`, and calls the real `KeConnectInterrupt`. Failure stops
before any GPU store. There is no caller-supplied ready flag or successful-owner
substitute.

The installed ISR does no SDK recovery or queued DPC work. It checks the pending
source, masks PMC interrupts, checks the immediate readback and publishes a
pending event only after that store succeeds. Unexpected readback records a
sticky failure; every subsequent entry/access refuses hardware work. The actual
SDK service body runs only in the command foreground and only after the real
SDK `pb_running=1` producer has executed. An early genuine IRQ remains pending
while that prerequisite is unmet. Required service has not been bypassed to
claim startup success.

The builder pins the original SDK core, generates a private diagnostic copy,
and routes **its actual compiled scalar/atomic load and store paths** through
the owner, including computed PRAMIN/USER pointers. It rejects unhandled LLVM
memory forms, preserves acquire/release access behavior, removes now-invalid
optimizer memory summaries, routes memory-copy/fill calls through ownership
checks, and polls at every compiled block terminator. The deadline is two
seconds plus a one-million-poll ceiling; counter reversal is an error. The
short checked MMIO transaction masks CPU interrupts so an ISR cannot insert a
failed write between the foreground's stop check and its store. Failure restores
CPU flags, unwinds that command and retains resources. Kernel operations also
check for an ISR failure on return before making another operation.

All DMA allocations use real kernel returns, page alignment, exact allocation
size/protection and contiguous physical endpoints/pages. They are pinned and
reverified before CPU initialization. Already returned RAM remains recorded and
retained even if an interrupt fails before its ownership can be validated.
The original instance-memory query, if reached, must establish its actual
reserved interval before PRAMIN stores; it does not resize the reservation.

The private SDK copy removes its failure/shutdown kill/free/restore paths and
its asynchronous handler installation. Debug/error UI stops instead of writing
display memory or sleeping indefinitely. The optional presentation DAC palette
reset is omitted because this diagnostic copies raw offscreen pixels before the
presentation DAC. The existing page 0 bootstrap sequence is retained and guarded;
there is no one-pointer relocation or fabricated system reservation.

## Current admitted prefix and exact stop

The closed policy currently admits only PMC interrupt masking/enabling, disabled
PCRTC/PTIMER interrupt fields, and a 16-bit PCI command bus-master update. The
original SDK's 32-bit PCI command/status RMW is replaced by the narrow command
update so status W1C bits receive no store. Every admitted effect receives its
immediate field readback; requested, observed and whether each operation occurred
are distinct result fields.

Actual offline execution of the unchanged remainder of `pb_init` reaches four
validated/pinned/zeroed allocations, the real event creation and four checked
stores, then stops **before** its original `FD001830=0` PCI ROM-control write.
No ROM-control write or corresponding readback has occurred. The preserved
requested value is not evidence of its physical effect. Original reset, clock,
tile, VGA PIO, FIFO transport and scanout operations farther downstream remain
guarded until their effect/readback/ownership contracts are reviewed. The
successful SDK-return certificate has not been produced, so `noise_gpu_capture`
refuses work. Linking all required functions is not full bootstrap admission.

The next concrete step is review of the original PCI ROM-control write and the
subsequent reset/clock/instance contract as one coherent bootstrap continuation.
Any allowed self-clearing, W1C, indirect-selector or reset effect needs its actual
contract; a generic latch or retry-on-mismatch is insufficient. The existing
console stop remains in force until the owner confirms recovery.

## Hardware-free qualification

```text
python tests/test_noise_gpu_bootstrap.py --output <private-directory>
python host/noise_gpu_bootstrap_build.py --output <private-directory>
```

The focused model executes the **actual target-linked PE initializer and ISR**
with independent kernel allocator/protection/pinning, exclusive IRQ and MMIO
providers. It includes the nominal real producer prefix; failed exclusive claim;
clock/stack/page preflight errors; invalid or overlapping allocation provenance;
post-pin change; real event error; immediate write/readback failures; elapsed
deadline; a second command during acquisition; and actual ISR interleavings
during connection, after a command write and during allocation. Failure retains
resources and prevents following hardware/kernel operations. A successful mask
publishes an early pending IRQ without manufacturing SDK readiness or calling a
queued DPC. No original `pb_init`, installer or ready producer is substituted.

These cases qualify the software owner and supported prefix. They provide no
silicon reset, physical selector, raster, tiled readback or noise algorithm oracle.
The earlier paired transport proof remains separate and unchanged.

The original SDK core and generated private copy retain the SDK's MIT attribution.
The host converter is compiled from the pinned SDK's GPL-2.0-or-later Cxbe sources;
generated objects, PE/XBE files, converted tool, captures and logs stay private.
Primary inputs are the [pinned SDK core and original bootstrap sequence](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/pbkit/pbkit.c),
[SDK IRQ/kernel interface and current-thread stack layout](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.h),
and the existing [original reserved page 0 evidence](https://github.com/mstan/xboxlle/blob/feat/blinx-audio-lle-20261009/pilots/native-title/GPU-COMPLETION-LLE.md).
