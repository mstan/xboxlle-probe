# Fixed read-only GP mapping query

The owner's standing authorization covers read-only checks, including unexpected
read outcomes. This distinct fixed batch uses the existing ARM-guarded EXEC
transport. It makes zero device stores, allocation/free calls, inherited SG RAM
loads, DSP starts, DMA/FIFO requests or storage/boot operations. It does not retry
the failed SG-address write or candidate-RAM load.

`src/gp_mapping_payload.c` resolves only kernel exports 173 and 174 through the
existing bounded PE32 export lookup. Their stdcall declarations and ordinals are
from pinned nxdk [xboxkrnl.h](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.h)
and [xboxkrnl.exe.def](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/xboxkrnl/xboxkrnl.exe.def).
The latter's SHA-256 is
`8aa3e48417c8a60aea8d1953bcc0674cdee95ce9a11e5e861d3107c3339d2527`.
`MmIsAddressValid` returns a one-byte BOOLEAN; upper EAX bits are not interpreted.
Its header comment contradicts its name and the agent's existing use. The payload
therefore first requires a result of 1 for the known kernel image base and 0 for
the fixed invalid calibration address `40000000`. It then checks the known base's
physical address is `10000`. A different result stops; no reversed interpretation
or physical query on a page reported invalid follows.

The payload reads GP reset `FE83FFFC`, AV `FD6806A0`, scratch SG address
`FE802040` and maximum `FE8020D4`, requiring reset 0, AV 11 and maximum 1544.
The SG base must be nonzero, aligned and leave four pages inside the 64 MiB
physical range. The 1545 eight-byte entries would occupy four pages. For each
direct CPU alias page, it calls only the validity query and, if valid, the
physical-address query. It never loads any candidate SG entry. A final read of
the same four device registers must match the initial values.

Successful return `D20000xy` records mapped-page bits in the low nibble and
matching physical-page bits in the high nibble. Zero bits are valid observations.
`DE000001` through `DE000006` identify failed export, BOOLEAN calibration,
physical calibration, fixed context/range, nonboolean result or final-context
checks. Mapping and expected aliasing establish neither allocation ownership nor
permission to read/write inherited SG bytes. No subsequent RAM access is part of
this batch.

The host requires the exact v0.4.0 identity, saves payload hash and private raw
results, and sends one EXEC only. Malformed reply, guarded stop or timeout stops
without retry, recovery store, relaunch or reboot. Thirteen hardware-free tests
execute the compiled x86, trap every store outside its stack and every inherited
RAM load, check all four pages/invalid-page behavior and callee preservation,
and exercise host identity/result/timeout stops. No device behavior is inferred
from those authored tests.

## First observation - 2026-10-10

The single fixed batch completed with `D2000000`: both API calibration checks
passed, all four inherited direct-alias pages were reported unmapped, and the
four ending device reads matched their starting values. No physical query was
made on a page reported invalid. There were eight device reads and zero device
stores, inherited-RAM loads, allocations or frees. The payload SHA-256 is
`99193391e5d26c991a14aa73ef3b054f7aa7aa852ab96e318ff2322a70a5532f`.

This rejects dereferencing that current inherited direct-alias range as mapped
RAM. It does not establish the cause of the earlier timeout in a previous
console context, SG ownership, SG-address encoding, GP bootstrap or bit-9 DMA.
The failed write/load were not retried. Any future experiment must use independently
owned and verified mappings. The combined hardware-free suite passes 105 tests;
one separate DSP checker test is skipped because its optional executable was
not configured for this run. Its earlier real-DSP execution evidence is retained.
