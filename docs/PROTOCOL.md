# Wire protocol

> [!WARNING]
> The protocol has no authentication or encryption. Use it only on an isolated, trusted
> network. `ARM` is an accident guard, not a security mechanism.

The Xbox listens on TCP port 4380 and accepts one client at a time. Commands and ordinary
replies are ASCII lines terminated by `\n`. Hexadecimal addresses may be sent with or
without a `0x` prefix.

## Read-only commands

| Command | Reply | Meaning |
|---|---|---|
| `PING` | `PONG xboxlle-probe v0.4.0` | Liveness and version |
| `INFO` | one JSON line | Agent, kernel, tick count, port, armed state |
| `STATUS` | `SAFE` or `ARMED` | Current session state |
| `PROBE CPU` | one JSON line | CPUID vendor, signature, and feature words |
| `PROBE NV2A` | one JSON line | Fixed, previously tested NV2A register reads |
| `PROBE CONTROLLER_S_HUB` | one JSON line | Fixed capability sentinel; current version does not inspect Controller S hardware |
| `QUIT` | connection closes | Stop this client session |

## Session arming

Send:

```text
ARM I_ACCEPT_THE_RISK
```

The reply is:

```text
ARMED
```

Arming lasts only for the current TCP connection. A new connection begins in `SAFE` state.

## Controller S hub capability sentinel

`PROBE CONTROLLER_S_HUB` is a fixed capability sentinel, not a hardware
inspection. The current agent's USB stack is not initialized. Its reply has
`available:false`, `hardware_inspected:false`, `usb_traffic:false`, and reason
`agent_usb_stack_not_initialized`; every descriptor, status, and enumeration
field is JSON `null`.

The command sends no USB control transfer, performs no OHCI access, and cannot
satisfy the Controller S descriptor-capture Bead. It does not infer a generic
hub identity or fabricate descriptor bytes. A future evidence capture requires
a separately reviewed and explicitly authorized active USB
initialization/enumeration design; it must omit string/serial and other
console-unique data.

## Armed commands

| Command | Reply | Meaning |
|---|---|---|
| `R <addr> <len>` | `OK <hexbytes>` | Guarded read, 1–4096 bytes |
| `RB <addr> <len>` | `OK <len>\n<raw>` | Guarded bulk read, 1–1 MiB |
| `W <addr> <hexbytes>` | `OK <n>` | Write guarded RAM or NV2A/MCPX MMIO |
| `EXEC <len>\n<raw>` | `RET <hex>` | Copy and call raw x86 code as `int(void)` |
| `L <Xbox path>` | `LAUNCHING`, then connection ends on success | Launch an XBE |
| `DASH` | `RETURNING`, then connection ends | Launch the configured dashboard path |
| `AV_HANDSHAKE` | one observation JSON line, then connection closes | One fixed FD6806A0 request toggle and bounded sampling; at most one attempt per agent lifetime |

Without arming, these return:

```text
ERR not armed
```

### Fixed AV handshake experiment (schema 1, agent v0.4.0)

`AV_HANDSHAKE` is an armed experiment, **not** a read-only `PROBE` command.
Its exact operation, evidence limits and review procedure are in
[AV-HANDSHAKE.md](AV-HANDSHAKE.md). It is rejected before any callback if
unarmed. The first armed attempt consumes a process-wide latch even if it
fails before writing; later connections cannot retry it.

The agent reads DWORD FD6806A0 twice, requires a stable initial 0 or 0x11,
writes `(~initial)&1` once, then records changes while polling that DWORD.
It stops at matching bits 0/4, an unexpected value, 100,000 post-write reads,
or 50 ms of performance-counter time. It never changes any other GPU register
or makes a second/restoring write. Reads that themselves hang cannot be bounded
by this software loop.

The JSON contains `probe:"av_handshake"`, `schema:1`, agent/kernel version,
`address:"0xfd6806a0"`, `outcome`, counter `frequency`, `reads`, `writes`,
`request`, `write_ticks:[begin_tick,end_tick]`, `trace`, and `last`. Each read
sample is `[begin_tick,end_tick,value]`,
with ticks relative to the initial counter observation. `trace` retains the
first word and changes (at most eight); `last` also preserves the final sample
if unchanged. No missing or unobserved state is interpolated. On an invalid
ending timestamp, `last.end` remains `last.begin` and the outcome is
`counter_backwards`; that interval is not a timing measurement.

`ack_observed` means only that bits 0/4 matched the new request within the
sampling limits. Other outcomes are `counter_invalid`, `counter_backwards`,
`initial_not_idle`, `initial_changed`, `unexpected_bits`, `trace_limit`,
`request_not_observed`, `time_limit`, and `read_limit`. The host prints valid
observations but returns an error for every outcome except `ack_observed`.
Malformed, contradictory or wrong-address observations also stop the host.
There are no automatic retries, recovery writes or relaunches.

`EXEC` can bypass every other guardrail and should be treated as complete control of the
running Xbox software environment.

The separately reviewed [fixed read-only AV context batch](AV-CONTEXT.md)
uses existing ARM/EXEC messages with a fixed six-byte DWORD-load payload.
It needs its own exact-operation approval; authorization for `AV_HANDSHAKE`
does not authorize EXEC. It changes no agent wire command or one-shot AV latch.

`R` and `RB` are transport operations, not declarations that a target range is harmless or
redistributable. They are armed because a prototype agent froze real hardware on an unsafe
read.

## Errors

Fixed follow-up host tools use existing ARM-guarded EXEC without new wire
commands or XBE changes: [read-only board context](BOARD-CONTEXT.md) and
[reversible display-bank selector observation](FP-BANKS.md). Their exact
effects, authorization scope and stop conditions are documented separately.
The [owned-RAM FE fence experiment](FE-FENCE.md) also uses existing EXEC;
it changes no wire command or Xbox agent implementation.

The [reverse AV request](AV-REVERSE.md) and [one-pixel valid-window and read-only
mode context](FP-ACTIVATION.md) follow-ups also retain the existing ARM/EXEC
protocol and one-shot AV_HANDSHAKE latch. Their fixed effects and stop conditions
are documented separately. The owner explicitly permits read-only checks and
benign volatile writes without repeated prompts; dangerous operations require
separate approval and should be avoided where possible. This authorization
does not weaken the ARM gate or permit retries after failed hardware operations.

The [fixed read-only GP context](GP-CONTEXT.md) also uses existing ARM/EXEC
without starting a DSP/DMA, changing SG pointers or adding a wire command.

Errors are one-line strings beginning with `ERR`. Clients must treat unexpected replies,
timeouts, short bulk transfers, and malformed JSON as failures. They must not retry hardware
operations automatically.

## Address allowlist

The current agent permits:

- validated low RAM pages below `0x08000000`;
- reads and writes in `0xFD000000`–`0xFDFFFFFF` for NV2A/MCPX MMIO;
- reads in `0xFF000000`–`0xFFFFFDFF` for flash mirrors.

Flash writes are refused. The final 512 bytes of the flash mirror are excluded because a
prototype agent froze real hardware while reading the top-of-memory MCPX region.
