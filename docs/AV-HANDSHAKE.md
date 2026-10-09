# Bounded NV2A AV handshake observation

Prepared for `beads-xbox.1.111`, a dependency of the Blinx LLE startup family
`beads-xbox.1.109`. **Offline preparation is not hardware qualification.**

The owned original AvSetDisplayMode routine reads FD6806A0 until bits 0 and
4 agree, programs its display controls, then writes `(~saved_value)&1`.
The request/acknowledgment interpretation is a hypothesis from that caller.
Pinned xemu's default zero read and ignored write do not establish the actual
register's state transition or its relationship to display timing. No original
kernel code, emulator implementation or private capture is included here.

## Exact proposed operation

After the owner separately authorizes deployment/launch of this XBE and this
experiment on an identified console:

Proposed deployment uses `E:\Apps\xboxlle-probe-av-handshake\default.xbe`,
separate from the existing agent. Do not overwrite the existing installation.
Creating this folder/uploading the file and launching that exact path need
authorization or may be performed manually by the owner.

1. The existing homebrew startup selects 640x480x32 using nxdk, shows its warning
   and starts the network agent. Launch itself changes the console's running
   application and display state; this must be included in the authorization.
2. The host arms one connection and sends `AV_HANDSHAKE` once.
3. The agent reads **only DWORD FD6806A0** for this experiment. Two initial
   values must agree and be either 0 or 0x11; any other value stops before
   a write. These are experimental preconditions, not an exhaustive assertion
   about the register's valid values on hardware.
4. It writes **one DWORD, `(~initial)&1`, to FD6806A0**. This matches the original
   caller's command encoding. No other MMIO, RAM, storage, EEPROM or flash
   write is part of the experiment. Ordinary application/network activity
   continues; this is not a claim of zero system activity.
5. It samples that register, with performance-counter brackets, until bits
   0/4 match the request, an unexpected observation occurs, 100,000 post-write
   reads occur, or 50 ms elapses. The loop never fabricates a pending state.
6. It reports observations and closes the connection. **There is no second
   write, reset, restoration, automatic retry, reboot or dashboard return.**
   The request phase may remain inverted after a successful observation.
   The agent refuses another attempt for the rest of that application lifetime.

This does not change mode-register values, but the effect of submitting the
existing programmed state is what is under investigation. Unchanged visible
output cannot be promised. A stuck MMIO read or frozen console cannot be
recovered by a software deadline. Stop for human inspection on unexpected
state, timeout, loss of video or network; do not automatically relaunch.

## Review and manual invocation

Review `src/av_handshake.h`, the fixed-address callbacks in `src/main.c`,
the host `av-handshake` command and [protocol](PROTOCOL.md). The host requires
the explicit risk flag before sending the armed command:

```powershell
python host/xbox_probe.py --host <owner-supplied-target> --i-accept-the-risk av-handshake
```

This command is documentation, not authorization to connect. Before execution,
the human must identify the exact Xbox, confirm ownership/authorization, a
trusted non-exposed network and backups of irreplaceable storage, and authorize
the exact launch/deployment and register experiment under [AGENTS.md](../AGENTS.md).
The human can deploy and run it manually instead. Keep raw results private.

## What the evidence can establish

- Which initial value was actually observed, which request was written, and
  which subsequent values were actually sampled.
- Whether a pending value was observed and whether the original caller's
  equality condition eventually became true. The lack of a pending sample
  does not prove that no pending interval existed.
- Performance-counter intervals bounding observations, including probe
  overhead and scheduling. The result does not identify the exact electrical
  acknowledgment edge or derive console refresh rate.

One observation cannot establish reset defaults, both transition directions,
timing-bank contents, or whether acknowledgment is tied to HSYNC, VSYNC or
another event. Those questions remain open unless corroborating evidence
settles them. Do not implement instantaneous success or copy the observed
initial value into an emulator reset state on this evidence alone.

## Offline validation

`python -m unittest discover -s tests -v` checks the actual C control loop with
scripted MMIO/clock callbacks, plus loopback protocol tests. Cases cover both
request directions, immediate/pending acknowledgments, arming, repeated calls,
unexpected values, unstable initial state, backward/stopped clocks and finite
poll limits. No test connects to an Xbox. `python -m py_compile
host/xbox_probe.py` checks the client. Build the XBE with the pinned nxdk;
building does not authorize deployment or execution.

Prepared on 2026-10-09: all 17 offline tests and client compilation pass.
The XBE builds with pinned nxdk `29638d0b001f179b73c3513489af10ddc2986216`.
The ignored local artifact is `bin/default.xbe`, SHA-256
`421405527c8e1d80ed70a7da04d682b3637fcebd7cd9518f8d0f29b317b4cc96`.
It has not been deployed or run on hardware. Linker output includes the
existing `.edata=.rdata` merge warning; compilation and XBE/XISO generation
complete successfully. No title-runtime or LLE family gate is closed here.
