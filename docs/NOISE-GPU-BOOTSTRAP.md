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
The original instance-memory query, if reached, validates and pins its CPU
reservation; it does not resize it. That return alone does not establish the
physical PRAMIN aperture alias, so PRAMIN writes remain guarded independently.

The private SDK copy removes its failure/shutdown kill/free/restore paths and
its asynchronous handler installation. Debug/error UI stops instead of writing
display memory or sleeping indefinitely. The optional presentation DAC palette
reset is omitted because this diagnostic copies raw offscreen pixels before the
presentation DAC. The existing page 0 bootstrap sequence is retained and guarded;
there is no one-pointer relocation or fabricated system reservation.

## Current admitted prefix and exact stop

The closed policy admits PMC interrupt masking/enabling, disabled PCRTC/PTIMER
interrupt fields, and the bounded PCI controls below. Every admitted MMIO write
uses an aligned DWORD transaction with its immediate readback. The earlier
halfword command adapter was corrected: normal PCI field widths do not establish
narrow-access support through the PBUS MMIO alias. Primary BAR0 documentation
requires aligned DWORD accesses outside the VGA aliases.

| PCI alias | Requested effect and readback |
| --- | --- |
| `FD001804` command/status | Preserve the observed command and set bus-master bit 2. Write **zero** to the upper STATUS half so no W1C flag is acknowledged. Compare the command half on immediate DWORD readback; read-only/sticky status remains separately observable. |
| `FD001830` ROM BAR | Clear decode-enable bit 0 while preserving the entire observed address and other fields. Check the current value again within the checked transaction; a changed value stops before the store. Compare the entire immediate DWORD readback. |
| `FD00180C` miscellaneous PCI header | Require a type-zero header and inactive BIST. Preserve the header, multifunction and BIST half; request cache-line size 0 and latency 248 clocks in the lower half. Recheck the same context before the store and compare the complete DWORD readback. |

The command and header values are also rechecked within the same interrupt-masked
transaction before publication. An observed ownership/context change stops
before the pending store. Requested and observed values and whether each operation
occurred remain distinct result fields. There is no retry, rollback or fallback.

Actual offline execution of the unchanged remainder of `pb_init` reaches four
validated/pinned/zeroed allocations, the real event creation and six checked
stores, then stops **before** its original `FD000200=FFFFFFFF` engine-enable
write. The request has no write or corresponding readback. The SDK's earlier
read of old PMC_ENABLE for its backup is preserved; it is not a readback of that
unperformed request. Original reset, clock, tile, VGA PIO, FIFO transport and
scanout operations farther downstream remain guarded. The successful SDK-return
certificate has not been produced, so `noise_gpu_capture` refuses work.

## Remaining reset, clock and instance contract

The next exact request is the SDK's blanket `PMC_ENABLE=FFFFFFFF`. Primary PMC
documentation establishes that clearing an engine-enable bit generally resets
that engine and removes its MMIO range. It names PFIFO/PGRAPH/PTIMER/PFB/display
enable fields but leaves NV10+ bit 0 and some family-dependent fields unresolved.
The SDK and the primary hardware test both use all-one enables; that use does
not provide a complete NV2A effect or readback mask for every written bit.
This image retains the guard rather than admitting a fabricated full latch.
A continuation needs a justified NV2A enable policy and explicit treatment of
preserved/unsupported fields before admitting the subsequent real producers.

The audit identifies the following downstream requirements without executing
them or substituting ready state:

- The original NVPLL check must still compute 233333324 Hz from the actual
  coefficients and crystal constant; an unsupported coefficient stops. No PLL
  register write is required by this part of the SDK.
- PTIMER `CLOCK_DIV=56968` and `CLOCK_MUL=7629` are 16-bit ratio fields. Primary
  documentation requires a nonzero divider and `0 <= MUL <= DIV`; a safe owner
  must validate the existing intermediate ratio before sequential updates and
  use `0000FFFF` field readbacks, not full-value latches. The CPU command's
  bounded time source must remain valid across these GPU timer changes.
- PTIMER `ALARM=FFFFFFFF` is a compare producer, not a plain full-word latch.
  Bits 0–4 read zero; its defined readback is `FFFFFFE0`, and the alarm can set
  interrupt status even while that interrupt is masked. The existing interrupt
  owner must handle the actual event, not synthesize or clear it by polling.
- `MmClaimGpuInstanceMemory(UINT_MAX, &padding)` is the original query-only
  producer. The SDK uses its top, padding and five-page reservation to place
  RAMHT/RAMFC and clear PRAMIN. CPU page ownership must not be treated as an
  already qualified aperture alias. The primary NV4 RAMIN documentation is
  unfinished, and the retained original owner also keeps physical alias
  equivalence explicit. No PRAMIN write admission is currently present.
- Primary RAMHT fields establish its address/search encoding. The SDK's RAMFC
  value includes fields still named `UNK17` in the primary reference, with a
  differing initialization comment. A context latch with guessed masks would
  not establish context loading or safe physical ownership.

Any later self-clearing, W1C, indirect-selector or reset effect needs its actual
contract. The existing console stop remains in force until the owner confirms
recovery. None of these offline results is a physical PCI, bootstrap or noise
pixel observation.

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

The PCI continuation adds nonzero ROM address, sticky STATUS, multifunction and
BIST-result sentinels. Actual compiled transactions must preserve those fields.
It covers already-disabled ROM decode, incompatible/active header context,
changed command/ROM/BIST context before publication, and ignored or changed
command/ROM/cache/latency effects. The failing readback must be the last hardware
operation; resources remain retained and later bootstrap/capture entries do no
work. Five focused groups exercise 36 complete command lifetimes. The independent
PCI producer implements STATUS W1C and read-only header/BIST fields instead of
treating the full configuration word as a latch.

These cases qualify the software owner and supported prefix. They provide no
silicon reset, physical selector, raster, tiled readback or noise algorithm oracle.
The earlier paired transport proof remains separate and unchanged.

The original SDK core and generated private copy retain the SDK's MIT attribution.
The host converter is compiled from the pinned SDK's GPL-2.0-or-later Cxbe sources;
generated objects, PE/XBE files, converted tool, captures and logs stay private.
Primary inputs are the [pinned SDK core and original bootstrap sequence](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/pbkit/pbkit.c),
[SDK IRQ/kernel interface and current-thread stack layout](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.h),
and the existing [original reserved page 0 evidence](https://github.com/mstan/xboxlle/blob/feat/blinx-audio-lle-20261009/pilots/native-title/GPU-COMPLETION-LLE.md).
The PCI continuation additionally binds the pinned primary
[PCI fields](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/bus/pci.xml),
[PBUS alias](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/bus/pbus.xml),
[BAR0 access rules](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/docs/hw/bus/bars.rst),
[engine reset/enables](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/docs/hw/bus/pmc.rst),
[timer fields and producers](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/docs/hw/bus/ptimer.rst),
and [FIFO context fields](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/fifo/nv4_pfifo.xml)
by path and SHA-256 in the private target-builder report.
