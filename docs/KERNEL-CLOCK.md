# Read-only kernel clock provenance before GPU timer changes

The diagnostic uses the real kernel performance counter for its finite deadline.
Root's original-code audit identifies a board-port counter at `8008`, with a
frequency of 3,375,000 Hz, rather than GPU PTIMER or CPU TSC. That captured-kernel
proof does not identify a different live console implementation. The prepared
`host/read_kernel_clock.py` closes that observation gap before a timer-changing
diagnostic; it performs no timer change itself.

Every target payload is exactly six bytes: one `MOV EAX,[aligned DWORD]` followed
by `RET`. The address must be in the restricted kernel-image window. The host
validates the DOS/PE32 headers, image/header/section bounds and export table,
then resolves exports 126/127 to executable sections. It reads each small complete
body up to its first return, with a 128-byte body bound and a 128-DWORD total budget.
Alignment can read up to three neighboring bytes; no arbitrary address CLI or
bulk memory request exists. It verifies the complete captured counter/frequency
instruction signature, allowing relocation of kernel globals/loop target. A
different implementation stops for review rather than claiming equivalence.

Successful-end rereads verify stable headers and export entries. They are planned
observations after preceding success, never retries. Each received reply is saved
before validation; timeout, malformed data, invalid metadata, changed exports or
unrecognized code stops the batch and preserves partial evidence. There is no
retry, write, restore, relaunch or automatic follow-on diagnostic.

The existing v0.4.0 agent and ARM/EXEC gate are unchanged. The six-byte payloads
contain no store, port instruction, branch, polling or original kernel-service
call. The host does not execute the functions it reads. No GPU MMIO, XBE upload,
launch, dashboard return, disk, flash, EEPROM or boot operation is included.
Ordinary agent payload/network RAM activity still occurs.

Raw function bytes, metadata and replies must remain private, outside the
repository or under ignored `results/`. The result identifies these two live
clock functions, not a full firmware image/hash, counter calibration, rollover
interrupt/cadence, GPU ratio/alarm behavior, bootstrap readiness or pixels.

The owner's standing read authorization covers this benign read-only check, but
the existing stopped hardware session still requires owner inspection/restart
under [AGENTS.md](../AGENTS.md#mandatory-operating-rules). This preparation does
not clear that stop. Other operators must obtain their own authorization.

When the hardware session is cleared, use an exact owner-supplied target and a
new private output directory:

```text
python host/read_kernel_clock.py --host <owner-supplied-target> --output <new-private-directory> --i-accept-the-risk
```

Capstone must be available before connecting. Offline checks execute the actual
six-byte payloads, test metadata escapes/read budgets before provider access,
and verify stopped-session evidence/no retry. Original implementation cases use
the private hash-bound source fixture when available; no firmware bytes are
committed in tests. Preparation is not a live observation or hardware approval.
