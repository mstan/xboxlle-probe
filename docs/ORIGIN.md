# Origin and hardware provenance

`xboxlle-probe` was extracted from the `xboxlle` emulator project. Its first version was
committed on 2026-07-16 as a resident nxdk control/probe agent, followed by a fault-guarded
v0.2 after a real console froze on an unsafe top-of-memory read.

The original session demonstrated that the approach worked end to end:

- the XBE was built with nxdk and launched on an original Xbox;
- a host computer connected over TCP;
- CPUID characterized the real CPU;
- fixed NV2A registers were read from the real GPU;
- a permitted flash range was bulk-read;
- the agent rejected the previously dangerous top-of-memory range and remained alive.

Sanitized measurements from that session included:

| Component | Observation |
|---|---|
| CPU vendor | `GenuineIntel` |
| CPU signature | `0x0000068a` |
| CPU generation | Family 6, model 8, stepping 10 |
| CPU features | MMX, FXSR, SSE present; SSE2/SSE3 absent |
| NV2A `PMC_BOOT_0` | `0x02a000a3` |
| NV2A core PLL | Approximately 233 MHz from the observed PLL value |

The console address, storage identifiers, firmware hash, per-console metadata, dumps, and
unsanitized logs are deliberately not included.

The original reusable agent and host driver were tracked in Git. Some one-off PCI and SMBus
probe scripts created during an interactive AI-assisted session were not preserved. This
standalone repository therefore begins with source-controlled CPU and NV2A named probes;
future probes should be implemented as reviewed source, return structured output, and be
validated deliberately on hardware.
