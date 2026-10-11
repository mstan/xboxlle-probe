# Original PLL access-width comparison

This is a prepared **read-only** operation, not a physical observation. It uses
the existing v0.4.0 agent without an upload, launch, kernel service or protocol
change. The owner's standing read authorization applies only after the prior
unexpected SG write's stop is cleared by human inspection or a power cycle,
as required by [AGENTS.md](../AGENTS.md), rules 8 and 9. Do not automatically
retry any failed read or use this preparation to clear that stop.

The retained original Blinx startup performs a DWORD load, a byte load at
offset +1, then another DWORD load on each NVPLL/MPLL/VPLL coefficient. The
maintained software currently extracts that byte. General BAR0 documentation
recommends aligned DWORD accesses, and the newer GPU diagnostic rejects these
byte accesses. Neither establishes what the actual NV2A byte load returns.
This comparison resolves only that reached read behavior; it grants no broader
MMIO or write admission.

The names and addresses come from pinned envytools
`f102b82381f3f11cee113d16374c87091db039d9`,
[PRAMDAC fields](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/display/nv3_pramdac.xml).
The [BAR0 access advice](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/docs/hw/bus/bars.rst)
is retained as a distinction from the original caller's actual accesses.
Original instructions, title logs and images remain private.

| Register | Fixed successful sequence | Expected comparison |
| --- | --- | --- |
| NVPLL | DWORD `FD680500`, byte `FD680501`, DWORD `FD680500` | Byte equals bits 8..15; DWORD remains unchanged |
| MPLL | DWORD `FD680504`, byte `FD680505`, DWORD `FD680504` | Same comparison; a zero coefficient is permitted |
| VPLL | DWORD `FD680508`, byte `FD680509`, DWORD `FD680508` | Same comparison |

Every DWORD payload is six bytes: `A1 <address:u32le> C3` (`MOV EAX,[address];
RET`). Every byte payload is eight bytes: `0F B6 05 <address:u32le> C3`
(`MOVZX EAX,BYTE PTR [address]; RET`). The sole result is EAX; each payload
performs one listed load and a return-stack load, with no memory or port write,
branch, loop or call. ARM remains mandatory for every EXEC.

The host refuses other address/width pairs, an existing output directory,
unaccepted risk or a different agent. It sends at most nine EXEC requests.
Received replies are flushed before validation; the pending attempt is saved
before sending. Malformed/all-ones replies, a byte above 255, disagreement,
changed coefficient or timeout stop immediately with partial private evidence.
The final DWORD is a planned stability observation after successful earlier
reads, never a retry. No following probe, recovery store or rearming follows a
failure. A failed byte comparison can also reflect a concurrent mode change;
the host stops instead of trying to distinguish causes by further reads.

After the existing stop is cleared and the fixed operation is authorized:

```text
python host/read_pll_widths.py --host <owner-identified-host> --output results/<fresh-private-directory> --i-accept-the-risk
```

Run the focused hardware-free checks with:

```text
python -m unittest discover -s tests -p test_pll_widths.py -v
```

The checks cover actual x86 payload loads/caller state, both protocol lengths
over loopback, fixed scope, failed identity/ARM, immediate stopped-session
evidence and timeout without retry. They do not establish physical alias
behavior, halfword access, PLL writes, reset/clock phase, GPU startup, PRAMIN
ownership or pixels. A successful observation remains current-mode evidence
for these three byte aliases, not general hardware access semantics.
