# Owned-memory GP bootstrap marker

This prerequisite for the bit9 experiment runs under the owner's standing
benign volatile-write authorization, after verified recovery backups. Existing
v0.4.0 identity and per-connection ARM/EXEC are unchanged. No XBE rebuild,
upload or launch is needed. This does not execute a descriptor DMA transfer,
enable audio/FE/setup/FIFO/EP/IRQs or change GPU/GPIO/boot/storage/EEPROM/flash.

The fixed `src/gp_boot_payload.c` is compiled as <=4096-byte freestanding x86
text with entry zero and no unresolved relocations. The host accepts no arbitrary
source, code, address, program or count. Before any device store it requires:

- GP reset FE83FFFC=`0`, IEN FE801004=`AFA`, SECTL FE802000=`7`,
  FECTL FE801100=`71F8F`, ISTS FE801000=`0`, and AV FD6806A0=`11`.
- The original scratch SG base must be nonzero/aligned within64MiB and its
  maximum1544. It reads the original X100 marker without dereferencing any
  inherited SG entry or copying firmware. The old marker must be a24-bit word
  distinct from the experiment's token.
- Bounded PE32 lookup of allocator/physical-address exports166/173 and
  performance counter/frequency126/127. Actual frequency must be3,375,000Hz.
- A newly allocated 28KB uncached/aligned physical range, exact direct alias,
  fully initialized and verified SG/boot data, then freshly rechecked context.

The allocation remains owned until restart, including on success or failure.
Its page0 holds512 SG entries; entries0..5 map the six subsequent owned pages,
and every remaining entry maps the owned guard. Pages1..4 hold a16KB authored
P image; page5 is spare sample storage; page6 is STOP-filled guard. The reference
bootstrap lead loads8KB from scratch; the allocation conservatively covers the
full16KB modeled P extent. All filler instructions are STOP, not original code.
No CPU direct write to GP P memory occurs.

The first six P words are authored instructions:

```text
65F400 0000FC   MOVE #FC,R5
44F400 5A34C1   MOVE #5A34C1,X0
021584          MOVE X0,X:(R5+4)  ; X100 marker
000087          STOP
```

The CPU never writes the token to the observed marker. Successful execution:

1. Installs the new physical SG base and maximum5, checking actual readbacks.
2. Releases only GP reset with value3, verifies it, then polls actual X100.
   Pending values may be the original marker or zero; token5A34C1 is required.
   Stop after100,000 reads or50ms (168,750 ticks), reject backward counters.
3. Verifies the six actual loaded GP P words and final word2047 of the reference
   boot extent, plus fresh quiet/reset/owned-SG state. This is independent device
   readback, not the CPU source buffer being accepted as loaded P.
4. Stops GP with reset0 and verifies it before restoring the old X100 word,
   then restores the original SG maximum/base with actual readback checks.

Success makes exactly seven DWORD device stores: two SG installation stores,
GP start/stop, the old X marker restoration, and two SG restoration stores.
Every restoration precondition is checked before its store. No unknown word
is copied into control. All other stores target the owned allocation or stack.
The old P image is not restored; GP is held in reset and its original SG source
is restored for a later ordinary bootstrap. This is volatile state, not boot
firmware or storage mutation.

Any failure stops at its stage, retaining the owned allocation/mapping rather
than freeing a possible late target or restoring a pointer before completion.
There is no subsequent host payload, retry, dashboard return or reboot. Failed
identity/ARM, malformed reply, unexpected value, timeout or loss of output/network
requires human inspection. A fault may leave GP running on owned storage or
reset held with that mapping; a normal restart recovers volatile state.

The factual offsets/masks are from pinned xemu apu_regs.h; its GP bootstrap
is a lead to test, not proof of hardware behavior. The generated six-word
stimulus is also executed offline on the existing pinned MIT DSP CPU
`c60aeedb6a6014850204c71e53bc0cf5b3104222`. That check requires actual X100
write and STOP, unchanged other X/Y words and no peripheral access. A changed
write target fails. It checks authored instructions, not hardware boot timing.
Nine focused tests cover actual x86 store/read whitelists, all512 SG entries,
API/alias/context failures, each failed store, bad loaded image, marker/time/
poll/backward-clock failures, callee state, and strict host stop behavior.
Set `PROBE_DSP_BOOT_CHECK` to the checker built from `tests/dsp_boot_check.c`
and the pinned existing DSP library to include that CPU check.

Positive observation qualifies only this supplied marker program in the
observed quiet context. It does not qualify retail GP firmware, descriptor
bit9, whole graph, output/frame signalling, EP/AC97, exact boot latency or
the full audio family. Raw results and source/payload hashes stay private.

## First hardware attempt (2026-10-10)

The payload returned `DF000008`: the first scratch SG-address store did not
read back as requested. All preceding allocation, initialization and context
checks passed. The payload stopped immediately, before the SG-maximum store
or GP reset release. No DSP start, descriptor DMA, audio enable or recovery
store followed. The new28KB allocation remains retained.

The return identifies the failed stage, but does not encode the requested
address or actual readback. It therefore establishes neither the mismatch
cause nor GP bootstrap behavior. The current SG base is unknown; do not free
its possible backing memory. Hardware requests remain paused for human
inspection under AGENTS.md rule8. No automatic retry is allowed. A later
read-only context check can characterize the stopped state after inspection.
