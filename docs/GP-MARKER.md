# Owned GP marker bootstrap: three closed phases

This is an offline source/contract review, not a hardware result or a network
runner. It does not retry the stopped SG write. Root must receive the owner's
restart notification and perform a fresh corrected16KiB owned preparation and
its separate successful exact SG calibration before considering this phase.
The old requested03E8A000/read03E88000 result cannot authorize a DSP start.

The only program is the six authored marker words already present in the owned
preparation: 65F400, FC, 44F400, 5A34C1, 021584, 87. Remaining words in the16KiB
source image are STOP. The finite program writes X100 and STOPs without a
peripheral, descriptor, frame, B0..B3, EP or output operation. The pinned actual
DSP checker executes these words and checks every X/Y word, real PC6, SP0 and
STOP. Hardware bootstrap behavior and the register encoding remain observations
to establish, not consequences of this instruction proof.

## Preconditions and exact owner identity

Retain the actual nine-page allocation, its pinning record, the lossless physical
reply, original SG reply, and the requested/readback calibration DWORD as separate
records. Compile all marker variants with the exact physical base and original
SG value from that successful generation; never round or mask either value.
The base must be16KiB aligned, nonzero and fit all36864 bytes below64MiB.
The actual original SG must also be16KiB aligned and differ from the new base.
No data at the original SG address is read.

Before any owned RAM load, each payload resolves the bounded kernel exports and
calibrates BOOLEAN in AL using known valid/invalid aliases. It checks validity,
actual MmGetPhysicalAddress and204 protection at the first and last byte of every
retained page, then actual36864-byte allocation extent. It validates the complete
provenance header, all2048 SG entries and all4096 P-source words. Table entries0..3
map retained source pages4..7; every remaining entry maps retained STOP guard
page7. Thus the unchanged maximum1544 stays within a completely owned table.
The pin must be supplied by the fresh preparation; there is no query claiming to
independently prove pin state here and no unlock/free/replacement.

The exact quiet floor is RESET0, IEN AFA, SECTL7, FECTL71F8F, ISTS0, AV11,
SG=new physical and MAX1544. A different context stops; no control writes create
it. Endpoints are checked again after ownership and time checks. The observation
variant requires RESET3 with the same other values. EP controls are never written.

The primary nxdk ABI supplies ordinals173/174/179/180 for physical/valid/protect/
extent and126/127 for the genuine kernel performance counter/frequency. Frequency
must actually equal3375000. Before any RESET write, the counter must advance
within64 calls, never go backwards, and bound preflight to at most3375000 ticks.
This is an execution bound; it provides no MCPX B3/configuration/rate admission.

## Three closed operations, manually ordered by root

1. **preflight** is read-only. After all checks it returns the actual X100 DWORD.
   Reject a non24-bit value or token5A34C1. Record this exact marker with the
   source and payload hashes. It is an initial observation, not a boot success.
2. **start** is separately compiled against that exact marker. It repeats the
   whole preflight and requires X100 still equal the initial observation. It
   performs exactly one requested device store, RESET=3, then returns the
   immediate raw RESET DWORD. No time, kernel, RAM or other MMIO operation follows
   the store/read. Only an actual returned3 permits a later observation request.
3. **observe** is a separate read-only payload and is never automatically called.
   It revalidates the retained owner, installed mapping, image, quiet endpoints
   and advancing counter with RESET3. It polls X100 at most100000 times and for
   at most168750 counter ticks (50ms) after that revalidation. Only the exact old
   marker or zero is pending; another value stops. Token then requires all2048
   actual P DWORDs at FE83A000..FE83BFFC to match the authored words/STOP exactly.
   Clock bounds are checked every64 P reads, followed by exact quiet/marker
   endpoints. Success D5000000|poll_count proves those comparisons in this
   observation, not an original firmware boot or timer.

The reset store is requested independently of its readback. Save raw replies
without relabeling them as a requested value. EXEC has only one EAX result: a
failed raw RESET value could coincide with a DF20 preflight failure code. Either
case stops; the result alone must not claim that the store did or did not occur.
Successful3 is unambiguous because every preflight failure uses a DF20 tag.

Any unexpected write readback, timeout, malformed reply or lost console/network
stops the entire session immediately. There is no retry, alternate pointer,
additional read, reset0 recovery, restoration, dashboard launch, unlock or free.
All retained RAM remains owned until an ordinary owner restart. A later failed
read-only observation also performs no recovery store. Even a successful marker
does not trigger another program, counter test or bit9 transfer automatically.

## Evidence and limits

The source-bound offline batch executes the actual extracted freestanding x86
for three aligned placements including03E88000 and zero/nonzero initial markers.
An independent model consumes real SG entries to form the loaded8192-byte image.
Exact raw reset mismatches, owner/API/protection/provenance/image faults, marker
and context drift, absent/stalled/backwards counters, time/count bounds and wrong
first/interior/last P words fail closed. Only stack stores and the one start RESET
store are permitted; the complete retained owner is byte-identical afterward.
The separate pinned DSP consumer proves actual marker instructions and a changed
target fails. The SG loader/readback/time models are explicitly authored offline
assumptions, not silicon results. The source and8192-byte profile lead are already
recorded in the mapped bootstrap evidence and pinned xemu investigation; no donor
implementation body or original firmware is included in these payloads.

The preflight's one-second bound includes owner verification; the observer's50ms
bound starts after that verification. A hardware/network stall cannot be cured by
a kernel counter and remains a host timeout/stop. A timestamp jump or observed
count cap is a failure, not evidence about DSP execution rate. MCPX may load a
different extent or use another reset/SG encoding; this experiment must report
that actual result without changing expected values to obtain success.

Original GP/EP bootstrap, B0..B3, bit9, coherent EP C5/CA/D5 startup, cadence,
frame events, AC97 and whole original-title output remain guarded. No default HLE,
shared DSP/APU owner, protocol, existing probe payload or root source is changed.

The source-bound preparation passes10/10 checks across70 compiled x86 contexts
in14.765973s, including actual pinned DSP marker/STOP and a wrong-target failure.
The payload is `src/gp_marker_payload.c`, the closed offline builder is
`host/gp_marker_build.py`, and tests are in `tests/test_gp_marker.py`.
The actual DSP case requires the reviewed `PROBE_B3_CONTEXT_CHECK` executable;
without it, that optional check reports a skip. These are offline results.
