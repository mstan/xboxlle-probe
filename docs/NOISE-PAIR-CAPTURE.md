# Offline paired DXT1 capture module

`src/noise_pair_capture.c` and `src/noise_pair_pbkit.inc` provide a finite
post-bootstrap capture module. They are **not wired into the resident agent**.
There is no upload, launch, network runner, automatic GPU initialization, recovery,
frame swap, filesystem write or resource release. The default Makefile, protocol
and SDK checkout are unchanged.

`host/noise_pair_build.py --output <private-directory>` compiles two Xbox-target
COFF objects using pinned nxdk `29638d0b001f179b73c3513489af10ddc2986216`.
The builder appends the authored helpers to a private copy of `pbkit.c` and adds a
success certificate at its single genuine successful `pb_init` return. No caller
can set a synthetic ready flag. This is an object build, not a complete XBE.

## Fixed post-bootstrap contract

The module requires the actual successful SDK owner, channel 0, an idle graphics
engine, the actual 640x480 ARGB8/Z24 SDK back buffer and a positive, advancing kernel
performance counter. Ownership is checked against retained SDK variables and
actual kernel physical translations. The module allocates and pins separate 4KiB
texture/write-combined and readback/noncached pages, verifies their protection,
size, contiguous translation and disjoint target ranges, and retains every page
on all paths. It never borrows an unknown object or initializes the GPU itself.

The authored microcase is an opaque 4x4 BC1 block, `71b50020e4e4e4e4`, nearest
sampling and six fixed inline vertices covering 8x8. Its program, sampler, target
clip, combiners and geometry are literal and identical in all four observations.
Both noise banks (`E0:50` and `DF:08`) are set and read back in the sequence
off/on/on/off. Each draw is followed by class 39 M2M from the actual SDK back
buffer into a different 256-byte span of the owned noncached readback page.
Four raw 64-DWORD snapshots and requested/observed controls remain in
`noise_pair_result`. No equality, difference or noise equation is assumed.

Push publication checks the owned linear ring capacity, physical continuity and
current USER PUT/GET. Each cache flush and submitted GPU job is bounded by 50ms
and 65536 reads. The actual PUT write is immediately read back; GET must remain
aligned within the submitted range and reach its end with PGRAPH idle and no
NSOURCE error. Each RDI selector/data write has an immediate expected readback;
the DATA check occurs before another selector read or write. Unexpected values
or a timeout latch a failure and cause an immediate return without additional
hardware operations, retry, cleanup, restore or fallback. A second capture call
performs no work after entry or failure.

The x86 offline model executes the compiled C against independent owned RAM,
allocation, control and GPU-work producers. Its GPU deliberately emits tagged
arbitrary bytes, then performs the actual declared row copy. It proves exact
transport, ordering and stop behavior; it does **not** validate raster pixels,
silicon noise, tiled readback or a complete GPU bootstrap. Run it with:

```text
python tests/test_noise_pair.py --output <private-directory>
```

## Remaining live prerequisite

Existing original Blinx GPU-driver evidence establishes physical page 0 as a
console-lifetime reserved D3D bootstrap resource. The matching SDK trigger
DMA context 12, initial zero GET/PUT, page 0 jump and sentinel are a coherent
original bootstrap sequence; a one-pointer relocation is unnecessary.

A complete live capture still requires a separately reviewed exclusive GPU
takeover and successful SDK bootstrap. Stock `pb_init`, its partial-failure
`pb_kill` paths and the installed ISR/DPC contain hardware operations and
unbounded waits outside this module's fail-stop boundary. They cannot be made
safe by wrapping the initializer in a host timeout. Establish bounded bootstrap
ordering, verified requested/readback effects, exclusive selector/ring/target
ownership and retained resources through its genuine success return. The
shutdown callback and ISR/DPC must also stop rather than recover after an
unexpected write. Only then wire this compiled module into a separately reviewed
diagnostic XBE and expose its retained result through a fixed read-only command.

The authored 8x8 packet and GPU M2M/tile interaction require a bounded first live
observation before they can supply an original draw 2 oracle. The actual enabled
noise algorithm and full graphics qualification remain open. This module does
not authorize or perform any console operation.

Primary source facts are the pinned [SDK owner, noise service and GPU bootstrap](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/pbkit/pbkit.c),
its [class 39 method definitions](https://github.com/XboxDev/nxdk/blob/29638d0b001f179b73c3513489af10ddc2986216/lib/pbkit/nv_objects.h),
and the primary [M2M input/output byte-increment fields](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/graph/nv_m2mf.xml).
The retained original-driver page ownership is documented in
[GPU-COMPLETION-LLE.md](https://github.com/mstan/xboxlle/blob/feat/blinx-audio-lle-20261009/pilots/native-title/GPU-COMPLETION-LLE.md).
