# Fixed reverse-direction AV observation

The owner authorizes benign volatile writes without repeated prompts.
This is a distinct successful-session follow-up to the completed one-shot
AV_HANDSHAKE command. Its latch remains consumed; the command is neither
called, reset nor weakened. Existing per-connection ARM remains mandatory.
The exact reverse operation runs once through reviewed EXEC, not a retry
of any failure. No XBE upload/launch is needed.

`src/av_reverse_payload.c` is compiled as freestanding 32-bit text with
entry offset zero, no unresolved relocation and <=4096 bytes. Before any
write it requires observed FP_TG_CONTROL=10100111, H/V totals935/524,
horizontal valid start0 and two consecutive AV FD6806A0 reads0. These are
current experiment preconditions, never reset values.

The payload writes one DWORD `1` to FD6806A0, then performs at most100,000
post-write reads. Only pending`1` or acknowledged`11` is admitted; unexpected
bits, wrong request, exhausted poll budget or precondition failure cannot
return success. The packed return reports the first post-write value and
actual post-write read count. No device value is fabricated. Counts are
not a hardware time measurement; no clock or exact sync-edge claim is made.
Ordinary callee stack activity is RAM, with no kernel call or allocation.

There is no second request, restoration, display timing/clock/enable
write, GPIO, APU/DSP, EEPROM, flash, boot or storage operation. Successful
phase remains`11`, as the original caller requests. A stuck register read
may still require restart. Identity/ARM, malformed reply, unexpected value,
network failure or a poll limit stops for human inspection, with the raw
reply saved privately and no retry/relaunch.

The host has no arbitrary source/payload/address argument. The shared
offline builder accepts only the reviewed FE variants and this reverse
payload. Its actual compiled instructions are exercised with independent
MMIO models, checking callee state, exact single store, both immediate and
pending observations, last permitted poll, changed preconditions, invalid
values and exhausted budget. Existing FE bytecode effects remain covered.

This can observe the opposite request direction in unchanged nxdk mode.
It does not establish reset state, mode activation, counter phase, timing
ownership or original title startup. Raw context and source/payload hashes
remain private with the recovery evidence.
