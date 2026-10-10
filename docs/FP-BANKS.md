# Reversible fixed FP timing-bank selector check

The owner authorized benign write checks on 2026-10-10. This experiment
changes only the documented READ_PROG selector (bit20) of FD680848. It
does not program display timing, clocks, enable bits, a mode request, GPIO,
APU, EEPROM, flash, boot configuration or storage. The existing v0.4.0
agent and its per-connection ARM guard are used; no upload or launch is
needed. Authorization is specific to this owner's session.

The actual closed x86 payload in `host/observe_fp_banks.py`:

1. Saves flags, ECX and EDX; reads FD680848 and requires exactly 10100111,
   as observed in the preceding read-only context. Otherwise it returns an
   error with no MMIO write.
2. Clears only READ_PROG with one DWORD write to FD680848.
3. Verifies actual selector readback is 10000111, then reads horizontal
   total FD680824 and vertical total FD680804, one DWORD each. A failed
   selector check skips both reads and continues to the planned restoration
   before reporting failure. No other timing register is read or written.
4. Reads fresh FD680848, sets READ_PROG to its original value, and writes
   that control back. Other fresh bits are preserved. This is the second
   and last MMIO write, part of the planned successful path, not a retry.
5. Reads actual control back and requires original 10100111; also requires
   both timing values fit twelve bits. Returns tagged packed totals or an
   error, restores caller registers/flags and returns. There is no loop,
   interrupt disable, function call or external input address.

This is at most six MMIO reads and two writes to the single control
address. Ordinary stack saves are also RAM writes. A stuck MMIO access can
still freeze the console. Failed ARM, identity, network, precondition,
width or restored-control checks stop the host with private evidence and
require human inspection. No automatic retry, extra restoring payload,
reboot or relaunch is sent.

[Pinned envytools definitions](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/display/nv3_pramdac.xml)
identify the selector and timing registers. This experiment observes totals
returned with READ_PROG clear; treating them as an active bank uses those
definitions. It does not independently measure output signals or prove
when FD6806A0 commits timing. Equal totals do not establish equality of
all other fields, instantaneous activation, reset values or counter phase.
