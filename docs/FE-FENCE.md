# Owned-RAM FE fence experiment

The owner authorizes benign volatile write checks and prohibits storage,
boot or hardware damage. This experiment targets only the audio FE and one
new, independently allocated RAM page. No DSP firmware, GP DMA descriptor,
voice, GPIO, display mode, EEPROM, flash, boot or storage operation is sent.
No XBE upload or launch is needed. Existing ARM-guarded EXEC is used once.

The original owned Blinx fence helper has the sequence SET_CONTROL_BIT0(1),
FEMEMADDR, FEMEMDATA, SET_CONTROL_BIT0(0), then reads its own RAM word. This
is observed caller programming, not a specification of which work the FE
must finish before publishing the token. The experiment tests basic token
transport in the already running probe application's context. It does not
introduce pending voice/DSP work or qualify its ordering.

`host/observe_fe_fence.py` compiles the fixed `src/fe_fence_payload.c` as a
32-bit freestanding raw text section. The entry must be offset zero, text
must be <=4096 bytes, and any unresolved relocation aborts before connecting.
No arbitrary payload/source input is accepted. Source and actual payload
hashes are saved with private results. Hardware-free tests execute these
same compiled bytes in an x86 emulator, not a separately reimplemented
controller.

The closed payload:

1. Requires FE801510 exactly `1` before allocation or device writes.
2. Validates the kernel's PE32 header/export bounds at the fixed Xbox
   kernel base. It resolves only nxdk's named ordinal facts for
   MmAllocateContiguousMemoryEx (166) and MmGetPhysicalAddress (173).
   It never copies or dumps kernel functions, follows export strings or
   accepts caller-supplied kernel addresses.
3. Allocates one 4096-byte, 4096-aligned page within physical 64MiB with
   PAGE_READWRITE | PAGE_NOCACHE (204). Checks actual physical translation,
   alignment and the conservative direct-mapped virtual address. It
   initializes and reads back a sentinel only in that newly owned page.
   Unsupported mappings or allocation errors fail before any APU write.
4. Rechecks FE control `1`, writes control `1`, owned physical address to
   FE801324, token to FE801334, then control `0`. These four DWORD stores
   are the original caller sequence. The CPU never writes the token into
   the observed RAM word.
5. The distinct `--held-window` variant first reads scratch up to 1000 times
   while control bit0 is still `1`, stopping on the token or an unexpected
   word. It adds no MMIO writes and records whether the token was already
   visible before control release. The default experiment has no such
   observer. Actual FE control reads must both equal `1` around that
   observation window; changed values cannot qualify. This is sequential
   sampling, not an atomic exclusion of other kernel writers. Each variant
   then reads actual uncached scratch for at most
   100,000 post-release loop iterations,
   stopping on the token or an unexpected RAM word. It makes one additional
   terminal read. This is a poll bound, not a timed delay measurement.
6. Performs the planned restoration of control bit0 to `1`, retaining
   any fresh unrelated bits, and checks actual control readback. This is
   the fifth and last MMIO store. Changed unrelated bits, failed restoration,
   malformed token/return or timeout never qualifies as success.

**The owned page is never freed, including after success, timeout or other
failure.** A late device write must not reach memory reused by the agent or
kernel. At most one page is retained for this single experiment until a
normal console restart. Payload memory itself is separately allocated and
freed by the existing agent as usual; it is never the FE write destination.
There is no retry, extra restoring payload, interrupt disable, external
write address, reboot or dashboard return. A stuck device read or kernel
call can still freeze the console and require human restart.

The host verifies the running v0.4.0 identity, arms on the same EXEC
connection, preserves the received return before validation and stops on
any failure for human inspection. Raw context remains in a new private
directory. Positive evidence would establish only that this original
sequence delivered the token to this owned RAM and restored this control
in this application context. It would not establish busy queue ordering,
DMA completion, cancellation, interrupts, processor rounding, precise
latency or the full original audio DPC contract.

If the held-window variant observes a token before release, that is positive
evidence that bit0 does not universally block this basic transfer in this
application context. Not observing it in a finite window cannot establish
an absolute release gate. The variant is a new successful-session follow-up,
never an automatic retry of a failed operation. It owns a separate page;
prior pages remain retained until restart.

## Observed owner-session results - 2026-10-10

Both experiments completed using the existing v0.4.0 agent. The default
variant observed the device token on its fifth post-release poll. The
held-window variant observed the token before that payload released control,
with control reads `1` around the window; its first post-release poll also
saw the token. Both verified restored control `1`, made five FE stores each
and retained their distinct owned pages (8192 bytes total). Raw results,
addresses and timestamps stay private. No queued audio work was introduced.

The first raw payload was 888 bytes, SHA-256
`84d65df3bfbe6b3d0e457ea8886c75b7255001c6c4c3fe265b19246972edb8e4`;
its source is preserved in commit `524ee98`. The held-window payload was
968 bytes, SHA-256
`ec86e06791f593803dc226b8496ec47ef47c20f3ad120bb144bd10c20ad5e062`.
All 53 offline tests pass, including actual compiled payload effects and
host rejection of wrong variant/phase tags. Basic idle transfer is observed;
full FE fence ownership, active-work ordering and precise timing remain open.

Kernel API/ordinal/protection facts are from the pinned
[nxdk xboxkrnl header](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.h)
and [export declarations](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.exe.def).
Only factual declarations are used; no implementation body or owned Xbox
code is redistributed.
