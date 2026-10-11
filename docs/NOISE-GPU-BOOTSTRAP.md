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
interrupt fields, bounded engine and timer controls, and the PCI controls below. Every admitted MMIO write
uses an aligned DWORD transaction with its immediate readback. The earlier
halfword command adapter was corrected: normal PCI field widths do not establish
narrow-access support through the PBUS MMIO alias. Primary BAR0 documentation
requires aligned DWORD accesses outside the VGA aliases.

Both load and store paths enforce that rule before touching BAR0. Byte access
is exempt only at enumerated primary PRMVIO/PRMCIO/PRMDIO register aliases;
halfword access, nearby undefined byte addresses, and DWORDs crossing those byte
registers stop. The exception admits a documented width, not an otherwise
unsupported VGA write effect, whole VGA memory window or second display head.

The earlier `64261e2` generation and its frozen 25-case green report remain
preserved. That report demonstrates owner/order/retention under its original
model; **its permissive PBUS halfword-access assumption is superseded and is not
primary-qualified MMIO behavior**. Executing its actual retained PE once against
the corrected primary-derived BAR0 model causally rejects its first halfword
read of `FD001804`, before any PCI command write. This is an offline model
failure, not a physical observation. The corrected owner guards that access
before the provider and uses aligned DWORD transactions for its actual SDK
continuation.

| PCI alias | Requested effect and readback |
| --- | --- |
| `FD001804` command/status | Preserve the observed command and set bus-master bit 2. Write **zero** to the upper STATUS half so no W1C flag is acknowledged. Compare the command half on immediate DWORD readback; read-only/sticky status remains separately observable. |
| `FD001830` ROM BAR | Clear decode-enable bit 0 while preserving the entire observed address and other fields. Check the current value again within the checked transaction; a changed value stops before the store. Compare the entire immediate DWORD readback. |
| `FD00180C` miscellaneous PCI header | Require a type-zero header and inactive BIST. Preserve the header, multifunction and BIST half; request cache-line size 0 and latency 248 clocks in the lower half. Recheck the same context before the store and compare the complete DWORD readback. |

The command and header values are also rechecked within the same interrupt-masked
transaction before publication. An observed ownership/context change stops
before the pending store. Requested and observed values and whether each operation
occurred remain distinct result fields. There is no retry, rollback or fallback.

The preserved `6277102` generation stopped before the blanket engine-enable
request. The current private SDK copy replaces that one request with the bounded
owner below, then executes the original PLL calculation and adapted timer
producer. Actual offline execution reaches four validated/pinned/zeroed
allocations, the real event, thirteen checked stores, and the actual query-only
instance-memory API with five-page pinning and post-pin verification. It then
selects the documented RAMHT fields only while the real consumers are idle. It
stops **before** `RAMFC FD002214=00890110` in the nominal owned fixture. That
request has no store or corresponding readback. The queried reservation remains
intact; there are no RAMFC or PRAMIN writes. The successful SDK-return certificate
has not been produced, so `noise_gpu_capture` refuses work. The preserved
`fc749eb` generation stopped at RAMHT after eleven stores; its proof and source
snapshots retain that earlier scope.

## Bounded engine, timer and instance contract

The original SDK request is blanket `PMC_ENABLE=FFFFFFFF`. Primary PMC
documentation establishes that clearing an engine-enable bit generally resets
that engine and removes its MMIO range. It names PFIFO/PGRAPH/PTIMER/PFB/display
enable fields but leaves NV10+ bit 0 and some family-dependent fields unresolved.
The SDK and the primary hardware test both use all-one enables; that use does
not provide a complete NV2A effect or readback mask for every written bit.
The generated diagnostic copy changes this request to `observed | 00001100`,
enabling only the documented PFIFO/PGRAPH fields. Preflight requires PGRAPH,
PTIMER, PFB and PCRTC already enabled, before reading their MMIO. Framebuffer,
timer, display and active graphics engines are never disabled or reset. A
disabled PFIFO is not read before enabling it; an already enabled PFIFO must
have no pending interrupt. All unresolved and variant-dependent enable fields
retain their actual observed value, and any changed complete readback stops.
This is a constrained diagnostic policy, not equivalence to the SDK's all-one
write or a claim that unknown fields are inert.

The checked transaction revalidates the enable value, exclusive owner, all
three masked interrupt controls and quiet PMC/PGRAPH sources before the store.
After immediate exact readback it checks actual PMC/PGRAPH/PFIFO status again.
No source is acknowledged to advance startup. A pending source or changed
context stops; no reset, ready certificate or completion is synthesized.

The actual original SDK PLL calculation still runs. Its accepted source is
233333324 Hz. The adapter rereads that coefficient and revalidates it in every
timer transaction, without writing a PLL register. The documented ratio and
alarm producer then run as one owned sequence:

| Register | Owned effect |
| --- | --- |
| `CLOCK_DIV FD009200` | Preserve unspecified upper bits and set the defined low half to 56968. Require a nonzero old divider, old multiplier no greater than either old or new divider, and unchanged current context before publication. |
| `CLOCK_MUL FD009210` | After successful divider publication, preserve unspecified upper bits and set the defined low half to 7629. Require the exact previously validated current ratio. Zero old multiplier is a supported stopped counter. |
| `ALARM FD009420` | After successful ratio publication, request `FFFFFFFF`; documented bits 0–4 read zero, so the immediate defined value is `FFFFFFE0`. This arms a real compare, not a completion latch. |

Every timer store requires its actual preceding stage, PTIMER interrupt mask
zero, PMC hardware routing enabled, no asserted PMC source, unchanged PLL and
the actual expected current DIV/MUL values. Ignored writes or changes in the
preserved unspecified ratio bits stop at immediate readback. Real alarm status
may be pending while its interrupt is masked; the owner preserves it without
W1C acknowledgement and verifies that no PMC source has become asserted.

The command deadline is specifically scoped to the captured original-kernel
performance-clock producer: export126 reads board port8008 and extends its
counter using kernel rollover globals; export127 returns 3,375,000 Hz. Complete
function inspection found no GPU MMIO, RDTSC or called provider. Therefore this
captured producer is independent of GPU PTIMER ratio updates. The owner requires
that exact frequency and advancing samples before any GPU store. A matching
frequency alone does **not** identify another live firmware or prove its counter
implementation. Any physical timer invocation still requires the actual target
clock route to be established and the standing console stop to be cleared.
The private source proof does not qualify counter width, rollover cadence or
silicon converter phase.

The RAMHT continuation preserves every observed field outside the documented
NV2A address/size/search fields. It selects the original query's page-aligned
padding, a 4 KiB table and a 128-entry search; the nominal encoding is
`03000100`. Selection requires an enabled PFIFO and quiet PMC/PGRAPH/FIFO sources,
disabled cache push/pull access, idle hashing, DMA and semaphore acquisition,
clear semaphore errors, disabled reassignment,
empty cache/runout status and matching PUT/GET pointers. A busy consumer stops
before any control change. The owner then masks PMC with its own immediate
readback, rechecks that idle context and the entire prior RAMHT word, publishes
the selection and compares the entire immediate word. It checks the idle
context again and leaves interrupts masked at the following guard. It never
disables consumers or resets/acknowledges them to create that state. CPU flags
are restored on every guarded transaction failure.

This configures documented control fields without admitting a lookup, context
load or RAMIN consumer. The RAMHT table is not filled, the physical aperture
mapping is not established, and preserved unknown fields are not declared
inert. No background provider supplies a successful SDK return or ready state.

The remaining downstream requirements stay guarded:

- `MmClaimGpuInstanceMemory(UINT_MAX, &padding)` is the original query-only
  producer, now actually reached. Its CPU mapping/protection/physical pages and
  endpoint are validated, pinned and reverified. No resize or freeing occurs.
  A bounded private execution of the captured original export and complete body
  inspection confirms that `UINT_MAX` writes padding `10000` and returns top
  `83FF0000` without changing the existing 64 KiB reservation. Its sixteen CPU
  pages have contiguous physical provenance and protection `204` (read/write
  with write combining). This is a query, not an exclusive new allocation.
  In the pinned SDK, the returned CPU pointer is checked and reduced by five
  pages, then never used again. All RAMHT/RAMFC placement and clearing instead
  use PRAMIN plus the returned padding. These producers do not prove that the
  two addresses are the same physical storage. The primary NV4 RAMIN mapping
  documentation is unfinished, and the retained original owner also keeps
  alias equivalence explicit. No PRAMIN write admission is currently present.
- Primary RAMHT fields establish its address/search encoding. The SDK's RAMFC
  value decodes to `UNK17=44` using the primary field layout, whose initialization
  comment says `45`. The SDK itself records both its calculated `00890110`
  and a different observed `008A0110`. Those comments establish neither the
  field's meaning nor context-loading behavior. This entire next write stays
  guarded; accepting only its known address bits would not make it safe.

## Prepared instance-alias comparison and unmet preconditions

There is no compiled marker command or live runner. A future bounded comparison
needs a proved exclusive instance-memory owner and CPU-store permission before
any marker store. The query above, IRQ exclusivity and pinned pages do not alone
exclude another foreground user of the kernel's existing reservation.

The primary `NV10_PFB.PRAMIN_WR_PROT` at `FD100214` adds a separate restriction:
when ENABLE is set, writes to the final `(MASK+1)*10000` bytes of VRAM are
ignored unless they go through PRAMIN. CPU page protection `204` does not bypass
that GPU restriction. The original SDK later clears ENABLE, after the currently
guarded RAMFC request. This diagnostic admits no such protection transition.
Any future CPU-marker phase requires independently established writable
ownership and an already compatible, reverified protection state; it must stop
if those preconditions are absent.

Once those ownership facts are supported and a separate phase is reviewed,
the smallest useful comparison would retain the actual query's top, padding,
page/endpoint/protection/pin provenance and the quiet consumer context, record
all baseline words, and derive candidate aperture addresses from the original
producer without truncating or masking a pointer. It would choose distinct
markers for fixed first/last words of the five pages, perform CPU stores only
within the exclusive proved reservation, order them with a CPU store fence,
and check every immediate CPU readback. Bounded passive aperture reads would
then distinguish a matching alias from a nonmatching observation. CPU originals
would be restored with immediate readback only after an ordinary completed
observation and while ownership remains valid. An unexpected write result
stops at that result, makes no automatic recovery/restore operation, and retains
all pages and evidence. A mismatching passive read is evidence, not permission
to try another offset or PRAMIN write. Several matching words would qualify only
those measured locations, not a full aperture mapping or a noise algorithm.

No preparation here authorizes that operation. Current missing dependencies are
the exclusive reservation contract, existing CPU-store permission and the RAMFC
context semantics, before physical alias calibration and capture can follow.

Any later self-clearing, W1C, indirect-selector or reset effect needs its actual
contract. The existing console stop remains in force until the owner confirms
recovery. None of these offline results is a physical PCI, bootstrap or noise
pixel observation.

## Hardware-free qualification

```text
python tests/test_noise_gpu_bootstrap.py --output <private-directory>
python tests/test_noise_gpu_bootstrap.py --output <private-directory> --prior-image <retained-64261e2-PE-directory>
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
work. The PCI/owner cases exercise 36 complete command lifetimes. The independent
PCI producer implements STATUS W1C and read-only header/BIST fields instead of
treating the full configuration word as a latch.

The preserved final width generation exercised six groups and 46 complete
command lifetimes. Its cases invoke the actual compiled owner API within a real
active command, after original allocation/event/IRQ producers. Unsupported byte
and halfword reads/writes fail before provider access, an undefined neighbor is
guarded, a halfword over a VGA byte alias is guarded, and known VGA byte reads
return independent fixture bytes before the unchanged SDK continuation resumes.
A VGA byte write still stops before its unsupported effect. These authored API
inputs test access ownership; they do not assert new original SDK behavior or
produce readiness. The optional `--prior-image` observation reuses the preserved
pre-fix executable once and retains its exact failing access and identities;
ordinary test discovery does not require that private prior image.

The preserved `fc749eb` engine/timer/instance generation exercises nine groups and 79
complete command lifetimes, plus one independent elapsed-alarm check. Actual
target cases include a real PFIFO enable and an already enabled retained state;
missing required engines rejected before any GPU store; changed enable context
or unknown-field readback; actual pending interrupt sources; original PLL zero
and unsupported-frequency branches; invalid and stopped old timer ratios;
ignored DIV/MUL/ALARM effects; changed ratio context and unspecified upper bits;
masked pending alarm without acknowledgement; failed instance query/protection
or post-pin verification; and an actual failing ISR after divider publication,
before multiplier/alarm/query work. The independent timer model takes nominal
elapsed board ticks into a rational core-clock converter and real 56-bit
counter/alarm state; repeated status/time reads are passive. Fractional phase at
a ratio change is an explicit nominal model choice, not a silicon claim. The
ordinary compiled SDK caller, actual allocator/IRQ/event/query ABI and retained
resources remain the execution path throughout.

The current instance selection generation exercises ten groups and 97 complete
command lifetimes, including eighteen added RAMHT ownership cases. Its independent
provider decodes address, table size and search count from the pinned primary
XML rather than the C mask. It supplies actual empty/disabled FIFO consumers,
then exercises retained unknown-field sentinels; reassignment, cache access,
hash/DMA/semaphore acquisition activity, nonempty cache and unmatched runout pointers; a context change
after masking; drift of the prior table word; ignored mask/address/size/search
effects; changed unknown-field readback; and a real pending FIFO source after
publication, plus an actual failing ISR after the successful RAMHT publication.
The post-publication context check runs before CPU flags are restored, so that
ISR cannot fail and then be followed by unguarded foreground reads.
Unexpected write readback is the last hardware operation; no
RAMFC/PRAMIN access or later kernel work follows, resources remain retained, and
subsequent bootstrap/capture entries do no work. Every completed foreground
case checks restoration of the original CPU interrupt flag. The coherent batch
also retains the earlier allocator, IRQ, PCI, engine and timer cases against
the current actual linked initializer, plus the independent elapsed/alarm case.
The initial RAMHT generation and its 94-case report are retained separately.
Executing that exact earlier PE with an ISR delivered at its actual exposed
post-check entry reproduces two foreground register reads after the ISR's
unexpected mask readback. The corrected generation runs the post-check with IF
clear and stops after the failing ISR readback. This is a causal compiled-owner
failure and correction, not a physical console failure.

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
The byte exceptions additionally bind the primary
[VGA register groups](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/display/nv_vga.xml)
and their PRMVIO/PRMCIO/PRMDIO placement. The independent model reads those XML
width definitions instead of using the C guard's switch as its oracle.
Instance selection additionally binds the primary
[FIFO consumer and context ownership](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/docs/hw/fifo/intro.rst),
[puller/hash-table use](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/docs/hw/fifo/puller.rst)
and [PRAMIN write protection](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/memory/nv10_pfb.xml).
The original query body, reserved-page addresses and byte snapshots stay private;
the public source contains no captured kernel bytes.
