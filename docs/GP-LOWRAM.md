# Distinct low-RAM ownership prerequisite for the bit9 discrimination plan

This is offline preparation only. No hardware or network runner is provided.
The stopped requested03E8A000/read03E88000 observation is preserved, not retried.
Root must coordinate owner restart and review any future separate allocation and
calibration. The low-RAM builder cannot start GP/EP or perform a bit9 transfer.

The discrimination plan needs actual base B<=00600000 and16KiB alignment. The
ordinary SG interpretation of field B+6000 then selects an index no greater than
1542, within unchanged maximum1544, backed by retained page7. A plausible direct
physical interpretation points to distinct retained page6. At the endpoint these
are606000 and607000. These are candidate addresses, not inferred bit9 semantics.

## Exact allocation request and refusal to substitute addresses

The local pinned primary nxdk ABI declares MmAllocateContiguousMemoryEx ordinal166
as the five32-bit-argument @20 kernel API with HighestAcceptableAddress. The real
compiled x86 calls it with (NumberOfBytes=36864, Lowest=0,
Highest=00608FFF, Alignment=16384, Protect=204). The highest argument is the
inclusive last byte derived as00600000+9*4096-1, so the allocation owns all nine
pages while constraining its starting base to00600000. This deliberately requests
scarce low RAM; a normal allocation failure is an acceptable stopped observation.

NULL returns immediately: no owned RAM, pin, or later MMIO operation occurs.
For a nonzero result the code validates BOOLEAN in AL before obtaining the actual
physical address, then rejects zero, high, misaligned, mismatched CPU alias or
the existing SG base. There is no mask, rounding, address truncation, high-memory
fallback, second allocation attempt or reuse of a previous successful high base.
The API/protection/mapping model is an authored offline model, not a guarantee
that the physical console can allocate this range.

## Closed prepare, inspect and calibration contract

1. **prepare** has no host-selected RAM address. The quiet floor is exactly GP
   RESET0, IEN AFA, SECTL7, FECTL71F8F, ISTS0, AV11, a nonzero16KiB-aligned original
   SG below64MiB and maximum1544. Nothing changes controls to obtain this floor.
   Known valid/invalid kernel aliases calibrate actual mapping BOOLEAN in AL and
   MmGetPhysicalAddress. Every first/last byte of all nine returned pages is
   checked for mapping, actual physical continuity and204 protection, followed by
   actual36864-byte extent. Actual pinning is requested with ordinal175 and the
   whole mapping/physical/protection batch is repeated before any owned load or
   initialization. An invalid returned allocation is retained and never read,
   written, freed or used for a device store.
2. Owned pages0..3 contain2048 eight-byte SG entries. Entries0..3 point to owned
   source pages4..7; all remaining entries point to retained STOP guard page7.
   Pages4..7 are STOP-filled except for the existing six authored marker words.
   Page8 records47504F31, exact actual physical base, exact original SG and their
   checksum. The entire table and all4096 source words are independently reread
   and exact quiet/SG/max endpoints checked. Successful preparation returns
   D4000000|physical, preserving all26 physical bits. Decode and independently
   reject zero, >00600000 or non16KiB values; save source/payload/raw replies.
3. **inspect** is read-only and bound to that exact successful physical base.
   It repeats actual mapping/physical/protection/extent checks before any RAM
   load, then exact provenance/table/source checks and endpoints. It returns the
   actual original SG for matching against the separate initial context. It does
   not allocate, pin again, free, follow or load original SG memory.
4. **calibrate** is compiled against both exact replies. After the same checks it
   performs exactly SG_ADDRESS=physical and returns the immediate raw readback.
   No later MMIO, kernel, RAM or time operation follows the store/read. Only exact
   equality with the separately recorded requested physical address counts as
   matching. Every other raw word stops; no retry, restoration, DSP start or free.

EXEC returns only EAX. An unexpected raw readback can coincide with a DF30
preflight guard code; either stops and the value alone cannot prove whether the
store occurred. A successful exact low address cannot coincide with a DF30 code.
All validated pages remain owned/pinned until an ordinary owner restart. Root
stops immediately after unexpected write readback, timeout, malformed reply or
lost network/display, without any recovery request. This variant never unlocks
or frees an allocation, including one rejected before RAM access.

## Focused evidence and exclusions

Seven focused checks pass across59 actual compiled x86 contexts in4.825409s.
Root reviewed the implementation and verified217 retained source, binary,
context, RAM and proof identities. These checks qualify the preparation contract;
they do not establish physical allocation, SG encoding or DSP bootstrap.

The actual extracted x86 executes across three owned placements including the
exact600000 endpoint. The independent oracle checks the complete nine-page
producer bytes and actual SG entries that separate the two candidate addresses.
Prepare/inspect/calibrate compose with the actual returned bytes and exact
provenance. Aligned604000, actual old high03E88000, unaligned03E8A000/601000,
zero, wrong alias, missing/no-space allocator, bad BOOLEAN/protection/physical/
extent/pinning and corrupted provenance/table/source contexts stop before a
device store. Every unexpected calibration readback ends after its exact raw
read, with no followup kernel/RAM/device action and unchanged retained bytes.
The marker instruction proof and original24-builder/bit9 evidence are reused
from their frozen reports; no previous waveform or descriptor matrix is rerun.

The distinct files do not mutate the corrected general-RAM or marker payload,
their builders/tests/proofs, the protocol/closed live payload list, production
APU/DSP/HLE or root source. No CMake wiring or new third-party body is needed.
Actual low-RAM availability, physical SG calibration/encoding and bootstrap,
bit9, B0..B3, EP startup/wake, cadence and original output remain unqualified.
