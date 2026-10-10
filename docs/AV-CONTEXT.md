# Prepared read-only AV display context

Follow-up to the first authorized FD6806A0 observation in
[`xboxlle`'s GPU record](https://github.com/mstan/xboxlle/blob/feat/blinx-audio-lle-20261009/pilots/native-title/GPU-COMPLETION-LLE.md#first-authorized-av-handshake-observation---2026-10-09).
The earlier single-write authorization does **not** authorize this EXEC batch.
The host tool is prepared for separate exact-operation approval under
[AGENTS.md](../AGENTS.md). No new hardware operation is claimed here.

## Concrete operation for review

`host/read_av_context.py` verifies the running v0.4.0 agent, then uses the
existing `ARM I_ACCEPT_THE_RISK` / `EXEC 6` protocol. Every payload is exactly
six x86 bytes: `A1 <little-endian DWORD address> C3`, meaning
`MOV EAX,[absolute DWORD address]; RET`. It contains no MMIO store, I/O-port
instruction, branch, polling loop, kernel call or arbitrary input address.
Registers other than the return EAX and normal RET stack/instruction pointers
remain unchanged. The existing agent allocates/frees its small payload RAM
as usual; this is not a claim of zero ordinary RAM/network activity.

The fixed batch performs 22 distinct DWORD reads, followed by one final
FD6806A0 stability read: **23 payloads / 23 DWORD reads total**. The final read
is a planned stability observation, never a retry after failure. Each connection
must receive `ARMED` before EXEC. The existing one-shot AV write latch is not
changed and no second handshake command or raw write is sent.

| Address | Context |
| --- | --- |
| FD6806A0, first and last | Observed AV transaction word |
| FD680500 / FD680504 / FD680508 | NV/M/VPLL words |
| FD680600 | General control |
| FD680800 / FD680804 / FD680808 | FP vertical display end / total / CRTC |
| FD68080C / FD680810 | FP vertical sync start / end |
| FD680814 / FD680818 | FP vertical valid start / end |
| FD680820 / FD680824 / FD680828 | FP horizontal display end / total / CRTC |
| FD68082C / FD680830 | FP horizontal sync start / end |
| FD680834 / FD680838 | FP horizontal valid start / end |
| FD68083C | FP dither control |
| FD680848 | FP timing-generator control, including current read-bank selector |
| FD680880 | FP debug/clock control |

Names/offsets use factual definitions in
[`envytools` f102b823, nv3_pramdac.xml](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/display/nv3_pramdac.xml),
not copied implementation bodies. Register-definition evidence is not proof
of exact NV2A activation or clock routing. The AV word remains a separately
observed undocumented transaction; this batch does not give it new semantics.

`EXEC` is used to guarantee one aligned DWORD load rather than a compiler's
unspecified access sequence for the generic memcpy-based `R` command. EXEC
can execute unrestricted code in general, so the exact fixed payload/list
needs explicit approval even though these payloads only read device registers.
No new upload, launch, mode change, I/O-port, APU/DSP, flash, EEPROM, boot
configuration, disk or storage operation is included.

## Limits and stop conditions

The tool requires an exact owner-supplied host and risk acknowledgment. Raw
output goes to a newly created private directory and cannot overwrite an
earlier session. It saves each received reply before validation. Wrong agent,
refused ARM, timeout, malformed return, all-ones register word, non-idle AV word
or changed AV state stops the batch, preserves partial records and requires
human inspection/power cycle. There is no retry, restoration or automatic
relaunch. A stuck physical register read cannot be bounded by host timeout.

This is sequential, non-atomic context in the currently selected nxdk display
mode. It does not change the read-bank selector, so it does not establish both
programmed and active bank contents. Stable AV endpoints do not prove all
other registers stayed constant throughout the batch. Network time brackets
include transport overhead and cannot measure GPU synchronization edges.
Reset defaults, reverse transitions, commit ownership and exact HSYNC/VSYNC
timing remain separate questions. Partial data or a context read alone must
not close an LLE family gate.

Offline validation uses loopback mocks and executes the actual six-byte
payloads in an x86 emulator, checking one intended DWORD read, no stores and
callee-save register preservation. Offline success is not hardware approval.

After explicit approval only:

```powershell
python host/read_av_context.py --host <owner-supplied-target> --output <new-private-directory> --i-accept-the-risk
```
