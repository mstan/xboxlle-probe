/* Authored bounded PE32 export lookup; factual nxdk ordinal declarations.
 * No kernel implementation bytes, export strings or external input address.
 */
#ifndef XLLE_PAYLOAD_KERNEL32_H
#define XLLE_PAYLOAD_KERNEL32_H
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long long u64;
#define WORD(address) (*(volatile u32 *)(address))
#define HALF(address) (*(volatile u16 *)(address))
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
#endif
