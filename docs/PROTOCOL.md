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
| `PING` | `PONG xboxlle-probe v0.3.1` | Liveness and version |
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

Without arming, these return:

```text
ERR not armed
```

`EXEC` can bypass every other guardrail and should be treated as complete control of the
running Xbox software environment.

`R` and `RB` are transport operations, not declarations that a target range is harmless or
redistributable. They are armed because a prototype agent froze real hardware on an unsafe
read.

## Errors

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
