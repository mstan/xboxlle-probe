# Fixed RTC selector and data-alias observation

The owner explicitly permits read-only checks and benign volatile writes in
the current qualification task, with no further operations after unexpected
write effects. This batch changes only the RTC's current register selector.
It never changes a CMOS byte, clock value, NMI mask, device enable, storage,
boot setting or agent wire command. Existing ARM-guarded EXEC is retained.

The captured original kernel's CMOS signature checker writes a full-byte
index to port72 and reads port71. Previously, the maintained machine marked72/73
absent. Pinned xemu482088490c2d5983ed5e1eafbd09906157c1eca0 maps a four-port
RTC:70 selects seven bits,72 selects eight bits, and71/73 share its data port.
These are independent leads, not a physical observation.

`host/read_rtc_context.py` admits exactly four selectors:10,80,81,FF. Each fixed
payload saves FLAGS/EDX/ECX, excludes interrupts for its bounded instruction
sequence, writes the selector to72 once, reads71 and73 once each, returns the
packed bytes, and restores FLAGS/EDX/ECX. Both IF-enabled and IF-disabled
payloads are executed by the offline tests. Callee-saved registers and stack
ownership are checked. Only the three stack saves write ordinary RAM.

The expected initialized signature bytes are55,55,AA,AA, respectively, as
checked/repaired by the original kernel. Any different post-selection result,
timeout, malformed response or wrong agent identity stops immediately. There
is no retry, further selector write, recovery operation or automatic relaunch.
Fresh v0.4.0 PING precedes the first EXEC. Private raw evidence is preserved.

On success: four benign index writes, eight reads, zero CMOS data writes.
The selector is left atFF, which ordinary RTC users replace before accessing
their own register. The index ports do not reveal the previous selector, so
the host does not pretend to restore it. No lasting CMOS contents change.

This establishes only the selected current signature and data alias behavior.
It does not establish reset defaults, power-loss retention, oscillator/update
timing, IRQ8, NMI delivery, clock setting or every possible RTC index/mode.

The first physical attempt on2026-10-10 passed v0.4.0 PING, sent only its first
selection, and observed matching23 through71/73 rather than the expected55.
It stopped immediately after one selector write/two reads, with zero CMOS data
writes. The remaining three payloads were not sent. Human inspection was
requested; no retry or recovery selection followed. Equal data does not prove
selection, reset/retention state or exact alias decoding. Raw evidence remains
private. All111 hardware-free probe tests pass, including five new RTC tests;
this stopped hardware attempt is not relabelled as a passing batch.

The owner subsequently inspected a normal screen. A fresh PING returned the
expected v0.4.0 identity, confirming agent responsiveness despite the static UI.
No EXEC, selector retry or recovery write followed that inspection. The passing
liveness check does not qualify the stopped CMOS experiment.
