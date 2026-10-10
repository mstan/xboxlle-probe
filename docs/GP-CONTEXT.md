# Fixed read-only GP context

The owner authorizes read-only checks without repeated prompts. This batch
uses the existing v0.4.0 per-connection ARM/EXEC guard, with eight fixed
six-byte DWORD-load/return payloads and **zero device stores**. It does not
install SG pointers, dereference pointed-to RAM, inspect DSP program/data,
reset/start a DSP, trigger DMA/FIFO, play audio or touch storage/boot/flash.

| Fixed DWORD address | Observation |
| --- | --- |
| FD6806A0 | Starting AV phase, must be the established `11` |
| FE83FFFC | GP reset/control before |
| FE802040 | GP scratch scatter-gather address, not dereferenced |
| FE8020D4 | GP scratch scatter-gather maximum |
| FE802044 | GP FIFO scatter-gather address, not dereferenced |
| FE8020D8 | GP FIFO scatter-gather maximum |
| FE83FFFC | GP reset/control after, must match the first sample |
| FD6806A0 | Final AV phase, must remain `11` |

The factual register offsets are in
[pinned xemu apu_regs.h](https://github.com/xemu-project/xemu/blob/482088490c2d5983ed5e1eafbd09906157c1eca0/hw/xbox/mcpx/apu/apu_regs.h);
the GP MMIO aperture is at APU base plus `30000`. No emulator implementation
body is imported. The observed controls are current nxdk application context,
not reset defaults or independent evidence of bit9 DMA semantics, safe GP
takeover, SG entry encoding, or boot/framework behavior.

Wrong identity/ARM, malformed/all-ones reply, changed endpoints, timeout or
loss of console output/network stops for human inspection, saving raw results
privately. No failure is automatically retried. Hardware-free tests execute
every fixed payload and verify the exact read/write whitelist and host stop
behavior. This prepares later owned-memory design without executing it.

The distinct `--quiet-controls` batch substitutes four read-only DWORDs:
APU interrupt enable FE801004, setup control FE802000, frontend control
FE801100 and interrupt status FE801000. It retains the two GP reset and two
AV endpoint reads, for eight reads total and zero device writes. It does not
clear interrupt status or infer that observed control values establish safe
GP takeover. Payload tests cover both closed lists.

Preparation identified an essential dependency: xemu's GP bootstrap model
bootstrap loads `800` DWORDs (8192 bytes) from scratch into P memory. A design
that installs a single 4096-byte SG page and writes P directly before releasing
reset would not provide that bootstrap image. No such write has been executed.
Any later experiment must own and bound the entire boot source and sample/SG
storage, account for CPU/GP IRQ and setup-engine state, and observe completion
before restoring shared pointers. Emulator bootstrap behavior remains a lead
to verify, not independently qualified hardware behavior.

The observed follow-ups completed with GP reset `0` and AV `11` at both
endpoints. Scratch/FIFO SG pointers were nonzero; their maxima were1544/1.
The separate control batch observed IEN=`AFA`, SECTL=`7`, FECTL=`71F8F`,
ISTS=`0`. Under the factual masks in apu_regs.h, these samples have the
global interrupt-enable bit clear, XCNTMODE OFF and the frontend HALTED.
They do not establish reset defaults, CPU-writer exclusion or DMA completion.
No DSP/SG/control write has been performed by these batches.
