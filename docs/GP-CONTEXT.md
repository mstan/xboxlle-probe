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
