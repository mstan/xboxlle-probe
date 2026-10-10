# Reversible one-pixel valid-window observation

The owner authorizes benign volatile checks without repeated prompts and
advises against dangerous operations. This follow-up changes only horizontal
valid start FD680834 from0 to1 and back, a one-pixel crop within the existing
640-pixel valid window. **Pixel clocks, PLLs, sync starts/ends, line/frame
totals, display enable, GPIO, APU/DSP, EEPROM, flash, boot and storage are never
written.** It does not request an out-of-range scan rate or new mode. Display
content can temporarily lose the first valid pixel; a stuck access can still
require restart. The running v0.4.0 agent's ARM guard is used unchanged.

The closed freestanding x86 payload, `src/fp_activation_payload.c`:

1. Requires observed control10100111, H/V totals935/524, programmed valid
   start0 and stable AV11 from the preceding reverse observation. It checks
   selected alternate-bank valid start0 before changing any window field.
2. Writes programmed valid start1 and checks actual programmed readback.
   Reads the alternate-bank start before issuing any AV request.
3. Writes AV request0 once and permits only pending10 or acknowledged0,
   with at most100,000 reads. Reads the alternate-bank start after ack.
4. Restores programmed start0 and verifies actual readback; writes planned
   AV request1 once with the same100,000-read bound. This second transaction
   returns the starting phase; it is not a retry after failure.
5. Verifies alternate-bank start0 and restored selector10100111, then returns
   actual before/after field observations, whether each direction sampled
   pending, and combined post-write AV read count. No value is manufactured.

Every alternate-bank observation verifies the selector after clearing only
READ_PROG bit20, reads one DWORD, then restores READ_PROG preserving fresh
other control bits and verifies actual readback. Four such observations use
eight selector stores. Successful execution has exactly **12 DWORD stores**:
eight FD680848 selector stores, two FD680834 crop/restoration stores, and two
FD6806A0 planned request stores. No other device store, allocation, kernel
call, interrupt disable or external input address exists. Usual callee stack
activity is RAM. Existing one-shot AV_HANDSHAKE command/latch is unchanged.

Failed identity/ARM, precondition, unexpected readback, invalid AV state,
poll budget, network or restoration stops for human inspection, preserving
the raw return privately. There is no subsequent host restoring payload,
retry, relaunch or reboot. A failure after the crop store can leave that
one-pixel crop or a different AV phase until normal restart; clock and sync
configuration remains outside the payload's write list.

The register/read-selector names use factual definitions in
[pinned envytools](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/display/nv3_pramdac.xml).
Treating the selected alternate values as active timing uses those definitions.
Before/after fields are sequential samples in the current nxdk mode. If the
field is already1 before the AV request, that does not establish whether it
updated immediately or at an intervening event. If it changes only in the
later sample, that does not identify the precise commit edge or prove every
other timing field follows the same policy. No electrical waveform,
counter-origin, reset-state or original-title-startup claim is implied.

Actual compiled bytes are tested against independent bank models including
request-linked, immediate and unchanged publication, both pending directions,
bad preconditions, blocked/ignored selectors, failed window/phase restoration
and finite AV polling. Host validation rejects failed or incomplete results
without any retry. Source/payload hashes remain with private observations.

The distinct `--wait-window` variant adds a measured wait of at least50ms
after **each** acknowledged request, before the corresponding alternate-bank
read. It makes the same12 stores. It uses the actual kernel's
KeQueryPerformanceCounter/Frequency exports126/127, validated through the
bounded PE32 resolver. Before any selector/crop write it requires the same
observed3,375,000Hz frequency. Each wait requires at least168,750 counter
ticks, rejects backward counts and stops after at most2,000,000 loop calls
plus its origin call. The two waits also cover restoration, so a delayed
bank publication cannot falsely pass immediate cleanup. No kernel allocator,
I/O-port output, IRQ disable or extra hardware request is added.

The counter API declarations and ordinals are factual definitions from
[pinned nxdk header](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.h)
and [export declarations](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.exe.def).
Raw output records both payload and shared resolver-header hashes. The
finite wait tests execute actual compiled bytes, including 64-bit counter
values, delayed bank publication, invalid frequency/header, backward clock
and a stopped clock reaching its real call budget. A50ms observation cannot
exclude later activation or establish an exact electrical sync edge.

The subsequent `host/read_fp_mode_context.py` batch makes exactly ten fixed
DWORD reads and zero device stores. It brackets DEBUG_0/1/2 and programmed
horizontal valid/display fields with control and AV observations. The known
restored control, window and AV values must match; DEBUG_1/2 are observations,
not synthesized expectations. Every payload is one fixed DWORD load and return,
with unchanged ARM and no retry. Raw results remain private.

The additional factual register offsets and scale-test field names are in
[Linux v6.12 nvreg.h](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/nouveau/dispnv04/nvreg.h).
The author's [DFP mode setup](https://github.com/torvalds/linux/blob/v6.12/drivers/gpu/drm/nouveau/dispnv04/dfp.c)
uses DEBUG_1 for automatic versus explicit scaling and describes DEBUG_2 as
capable of overriding totals. This motivates read-only context collection;
it does not establish the NV2A valid-window publication rule, justify writing
those controls or attribute the measured result to an override without proof.
