/* Closed 32-bit EXEC probe. No upload, storage, GPIO, DSP or GPU operation.
 * The one independently allocated uncached page is NEVER freed: a timed-out
 * device may write it late. This bounds lifetime safely until console restart.
 * Original helper's ordering is evidence to test, not asserted semantics.
 */
typedef unsigned int u32;
typedef unsigned short u16;
#define WORD(address) (*(volatile u32 *)(address))
#define HALF(address) (*(volatile u16 *)(address))
#define FE_CONTROL 0xfe801510u
#define FE_ADDRESS 0xfe801324u
#define FE_DATA 0xfe801334u
#define TOKEN 0x5a34f00eu
#define INITIAL 0xa5cb0ff1u
#define LIMIT 100000u

/* PE32 export lookup, fixed Xbox kernel base; every computed read stays
 * within a validated <=16MiB image span. No export-name/string traversal.
 * nxdk xboxkrnl.exe.def: MmAllocateContiguousMemoryEx=166, physical query=173.
 */
static __attribute__((always_inline)) inline u32 kernel_export(u32 ordinal) {
    const u32 base=0x80010000u;
    if (HALF(base)!=0x5a4du) return 0;
    u32 nt=WORD(base+0x3cu);
    if (nt<0x40u || nt>0xf00u) return 0;
    nt+=base;
    if (WORD(nt)!=0x4550u || HALF(nt+0x18u)!=0x10bu) return 0;
    u32 size=WORD(nt+0x50u), table=WORD(nt+0x78u), span=WORD(nt+0x7cu);
    if (size<0x1000u || size>0x1000000u || table>size-40u || span<40u || span>size-table) return 0;
    u32 exp=base+table, first=WORD(exp+0x10u), count=WORD(exp+0x14u), funcs=WORD(exp+0x1cu);
    if (count>4096u || count>size/4u || ordinal<first || ordinal-first>=count || funcs>size-count*4u) return 0;
    u32 rva=WORD(base+funcs+(ordinal-first)*4u);
    if (rva<0x1000u || rva>=size || (rva>=table && rva-table<span)) return 0;
    return base+rva;
}

u32 fe_fence_probe(void) {
    typedef void *(__attribute__((stdcall)) *Allocate)(u32,u32,u32,u32,u32);
    typedef u32 (__attribute__((stdcall)) *Physical)(void *);
    if (WORD(FE_CONTROL)!=1u) return 0xfa000001u;
    Allocate allocate=(Allocate)kernel_export(166u);
    Physical physical=(Physical)kernel_export(173u);
    if (!allocate || !physical) return 0xfa000002u;
    /* nxdk PAGE_READWRITE=4, PAGE_NOCACHE=200. Exactly one owned page. */
    volatile u32 *scratch=allocate(4096u,0u,0x03ffffffu,4096u,0x204u);
    if (!scratch) return 0xfa000003u;
    u32 address=physical((void *)scratch);
    /* Conservative 64MiB direct-mapped profile, never guess a physical alias. */
    if (!address || address>0x03fff000u || (address&4095u) ||
        (u32)scratch!=(0x80000000u|address)) return 0xfa000004u;
    scratch[0]=INITIAL;
    if (scratch[0]!=INITIAL || WORD(FE_CONTROL)!=1u) return 0xfa000005u;
    /* Reproduce original SET(1), ADDR, DATA, SET(0), then observe actual RAM.
     * No completion is manufactured by the host or by this CPU payload.
     */
    WORD(FE_CONTROL)=1u;
    WORD(FE_ADDRESS)=address;
    WORD(FE_DATA)=TOKEN;
    WORD(FE_CONTROL)=0u;
    u32 polls;
    for (polls=1u;polls<=LIMIT;++polls) {
        u32 value=scratch[0];
        if (value==TOKEN) break;
        if (value!=INITIAL) break;
    }
    u32 last=scratch[0];
    u32 control=WORD(FE_CONTROL);
    /* Planned selector/control restoration, never a retry. Preserve fresh
     * unrelated bits rather than installing the old whole register word.
     */
    WORD(FE_CONTROL)=control|1u;
    if (control!=0u || WORD(FE_CONTROL)!=1u) return 0xfa000006u;
    if (last!=TOKEN || polls>LIMIT) return 0xf2000000u | (polls&0x1ffffu);
    return 0xf1000000u | polls;
}
