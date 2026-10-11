# Fresh owned-RAM SG calibration and B3 prerequisite

This is the corrected16KiB-aligned preparation contract, owned by `.113.15` and hardware investigation `.114`. The first4KiB-aligned hardware generation passed allocation and retained inspection, then returned03E88000 after its sole SG store requested03E8A000. The host stopped at that raw readback with no further hardware operation. Neither DSP started. Original GP/EP allocator traces independently require16KiB SG-table alignment. The corrected generation passes12 offline checks; it has not run on hardware. Hardware probing waits for owner restart/inspection. Root alone coordinates network operations under the owner's standing read/benign-write permission. The failed DF000008 store and unmapped inherited CPU aliases are not retried or loaded. No automatic hardware runner is supplied.

## Read-only context first

Use the existing fixed read-only GP/AV context tools once to establish the actual reset, IRQ, FE, setup-engine, SG address/max and AV endpoints. Do not dereference SG addresses. The exact preparation floor is GP reset0, IEN AFA, SECTL7, FECTL71F8F, ISTS0, AV11, nonzero aligned physical SG address below64MiB and maximum1544. A different floor stops; do not change controls to create this floor. If an unchanged original GP is already running, the earlier11314 read-only prefix/profile-word plan remains preferable and this preparation must not run.

## Phase1: fresh owned preparation; zero device stores

Compile gp_owned_build.compile_owned('prepare') with no host RAM address. Execute only the reviewed preparation generation, after root authorization/context review. It resolves factual nxdk kernel exports166 AllocateContiguousMemoryEx,173 GetPhysicalAddress,174 IsAddressValid,175 LockUnlockBufferPages,179 QueryAddressProtect,180 QueryAllocationSize. The BOOLEAN convention is independently calibrated against known kernel memory and an invalid address; use only AL. No invalid address is translated.

Allocate a fresh36864-byte,16KiB-aligned contiguous PAGE_READWRITE|PAGE_NOCACHE region constrained below64MiB. Before any owned RAM access, check allocator-returned mapping, physical address,16KiB table alignment, full extent and actual direct alias. Check the first and last byte of all nine pages using actual Valid/Physical/Protect results. Pin with LockUnlockBufferPages(base,36864,FALSE), repeat every page check, initialize, then verify all produced bytes used by the later phase. Retain all allocations and locks until ordinary restart, including any failed preparation; do not free/unlock a possible hardware target.

Pages0..3 contain2048 eight-byte SG entries, covering all1545 entries admitted by the unchanged max1544. Entries0..3 point to owned P pages4..7; every remaining entry points to owned guard page7, never to inherited memory or the provenance page. P pages4..7 are STOP-filled except for the six-word authored marker stimulus. The CPU never writes the observed DSP X marker. Page8 is a provenance header with magic, actual physical base, unchanged original SG and checksum. Both DSPs remain untouched.

Success satisfies (RET&FC000000)==D4000000; physical=RET&03FFFFFF. The tag leaves all26 physical bits free. Independently reject zero, unaligned or out-of-range decoded physical addresses; all DF10xxxx results stop. Save the exact reply, requested source hashes and physical base before constructing another payload. No automatic retry. Fresh preparation is not bootstrap evidence.

## Phase2: verify the retained ownership; zero device stores

Compile only the 'inspect' variant bound to that exact successful physical base. It checks every page mapping/physical/protection/extent before loading the retained RAM, validates provenance, all2048 entries, all4096 P words and fresh quiet/SG/max context. It returns the exact original SG DWORD. Match that with phase1's separately recorded initial read-only context; any difference stops. Existing generic R/high alias loads are not used.

This inspection binds a later store to the exact returned preparation and context. Its accepted address is never derived from an inherited SG register. The header is an ownership consistency guard, not an untrusted-code security boundary; EXEC already has full control.

## Phase3: a distinct one-store calibration; still no DSP start

Only after both stages and root review pass, compile 'calibrate' with the exact prepared physical base and exact inspected original SG. Hash/save that variant and requested physical value before any operation. The payload repeats all owner/table/image/context checks, then performs exactly:

1. SG_ADDRESS(FE802040) = exact prepared physical base.
2. Return the immediate raw DWORD readback from FE802040.

The sole EXEC reply therefore preserves both values: requested is already in the saved plan; actual is RET, including RET0 or RETffffffff. No later MMIO/API call, free/unlock, RAM record write, recovery store, SG-max change, DSP start or poll follows that read. Any nonmatching readback, malformed reply, timeout or lost network ends the entire experiment. Root sends no additional hardware request, including health PING or restoration, until owner inspection; no automatic retry. Mock readbacks cover ignored, zero, all-ones, low-bit altered, shifted and high-alias forms without assuming an encoding.

On exact match, GP is still held in reset and the new table safely backs unchanged max1544. A future restore/start operation is a separately reviewed owner action, not included here. The old SG mapping is not loaded, freed or claimed CPU-valid. Do not use the result alone as proof that DSP bootstrap fetches the table or that the register has a byte-address encoding beyond this observation.

## Bootstrap marker prerequisite after calibration

Do not add a GPstart fallback to this plan. A next distinct reviewed batch must reverify retained pages, unchanged quiet context and installed exact SG pointer. It must keep IRQ/FE/setup-engine/EP/audio idle, prepare a bounded max using immediate requested/readback evidence, use the owned STOP-filled image, and observe a DSP-produced X marker plus exact actual loaded P words. Establish a bounded time source and stop after any unexpected write without recovery. Retain the table/program even on timeout. Separate control-store readbacks must remain identifiable; the old gp_boot payload is not reused. Bootstrap success would cover only its authored program in that observed context.

## Minimal B3 context stimulus, still offline only

The builder exports authored_b3_image(): an independently authored103-word program in a STOP-filled16KiB image. It issues the reached original immediate configuration tuple B2=FFFFFF, B0=1, B1=1, then reads B3 three times around16-NOP and64-NOP finite intervals. It stores samples to X100/101/102, writes token5A34C1 to X104 and STOPs. There is no C4/C5/CA/D4/D5, event/yield, descriptor DMA, frame, EP or output operation. No bootstrap/start payload for this stimulus exists in the builder.

The pinned real DSP CPU check injects17/1009/5521 solely to verify exact instruction access, sample transport, four X targets, unchanged other X/Y/P, SP0 and STOP atPC103. Changed store target and changed configuration-address programs independently fail. Injected values are not admitted MCPX counter semantics. Actual B3 frequency, epoch, gate/config bit identity and response to yield are unknown. A future hardware B3 experiment requires the separately qualified owned-marker bootstrap prerequisite first, then an independently reviewed source-bound no-DMA program/start/stop/result contract. No guessed timer configuration behavior is introduced into production.

## Evidence and limits

Primary ABI inputs are local nxdk xboxkrnl.h and xboxkrnl.exe.def at29638d0b001f179b73c3513489af10ddc2986216. The local pinned xemu register offsets and SG/bootstrap code are investigator leads, not hardware proof. The earlier11314 primary/source-bound audit remains the reason B0/B1/B2 and physical B3 semantics are unresolved.

The new files do not alter the live probe protocol, existing closed payload list, root FP experiment, maintained APU/core, default fast HLE or original firmware. All hardware activity, title/playback operations and network operations are zero in the corrected offline generation. Full bootstrap, EP startup C5/CA/D5, bit9, cadence and original audio output remain guarded.
Sequential context samples are not an atomic exclusion of other CPU/MMIO writers. Root must establish the probe is the sole owner of APU configuration before any future calibration/start action; a changed context is a terminal stop, never a request to repair it.

The original4KiB generation, actual request/readback and corrected-generation artifacts retain separate private identities. A single cleared address bit does not establish the complete SG register mask. The stronger alignment follows original allocation semantics; exact requested/readback equality remains mandatory. No production APU address masking or bit9 behavior is inferred from this result.
