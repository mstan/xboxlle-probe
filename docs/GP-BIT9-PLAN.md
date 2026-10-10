# Owned-memory GP bit9 preparation

Tracked by central `beads-xbox.1.114`. The owner permits benign volatile writes
without repeated prompts and advises avoiding dangerous operations. This is
an offline design checkpoint, not an executed DMA observation or a pending
approval request. No hardware write is authorized by a document alone.

The observed context in GP-CONTEXT has reset held, the global audio IRQ gate
off and the frontend halted, but retained SG pointers. Do not start GP with
that inherited configuration or inspect/dereference its old pointed-to memory.
Do not enable the setup engine, CPU interrupts, FE processing, FIFO, EP/AC97,
audio playback, GPIO, storage, EEPROM, flash or a different display mode.

The next executable must satisfy all of these constraints:

1. Revalidate the actual idle/reset/IRQ/frontend conditions immediately before
   any store. Preserve original SG address/max words for planned restoration;
   fail before mutation if the established safe context is unavailable.
2. Resolve only the known contiguous allocator/physical-address and counter
   exports through the bounded PE32 resolver. Own uncached physical RAM for
   the **entire bootstrap image, SG table, sample data and guard buffers**.
   Validate exact physical aliases and all ranges before installing a pointer.
   Retain allocation until restart; never free a possible late-DMA target.
3. Initialize the whole boot source with authored bounded instructions, without
   any original firmware or kernel bytes. The reference bootstrap lead loads
   8192 bytes into P; direct writes to P before reset release cannot substitute
   for its scratch boot source. Account for a larger bounded P-memory extent
   conservatively and keep every supplied SG entry within owned pages.
4. Start with a baseline **input-only** scratch transfer and unit stride,
   matching the original reached format/count/Y destination but using owned
   source bytes. The DSP itself initializes its descriptor after bootstrap;
   do not depend on X fields surviving a boot ROM. Its finite program must
   expose actual data, descriptor writeback and completion/status observations.
5. Test the identical descriptor with bit9 set only after the baseline succeeds
   and restores state. These are distinct experiments, never retries of a
   failure. Do not infer that unchanged bytes prove every bit9 behavior:
   qualify the observed original shape, with explicit scope and omitted cases.
6. Establish completion before stopping GP and restoring shared SG pointers.
   A failed/timeout transfer must retain the owned mapping and page allocation;
   never expose a late device operation to inherited addresses or freed RAM.
   Stop for human inspection; no restoring host payload or automatic retry.
7. Test actual compiled x86 effects, allocator failure and alias/range guards,
   exact store whitelist, stale/changed contexts and finite poll limits. Also
   execute the authored DSP instructions offline, checking every peripheral
   effect and data field. Emulator tests validate the stimulus, not hardware
   bit9 semantics. Keep raw hardware results and original assets private.

The baseline is not ready for hardware execution until those constraints are
implemented and checked. If GP cannot execute independently with setup-engine
and IRQ/frontend state preserved, investigate that dependency rather than
enabling unrelated live processing. No full audio-family closure follows
from either successful bounded transfer.
