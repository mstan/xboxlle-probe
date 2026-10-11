/* Separate read-only preflight, single-reset-store start, and read-only
 * observation of an authored owned GP marker. No SG/max/FE/IRQ/EP/output
 * store, descriptor DMA, allocation/free, recovery or automatic fallback.
 */
#include "payload_kernel32.h"
#ifndef GP_MARKER_PHASE
#define GP_MARKER_PHASE 0
#endif
#ifndef GP_MARKER_PHYSICAL
#define GP_MARKER_PHYSICAL 0u
#endif
#ifndef GP_MARKER_ORIGINAL_SG
#define GP_MARKER_ORIGINAL_SG 0u
#endif
#ifndef GP_MARKER_INITIAL
#define GP_MARKER_INITIAL 0u
#endif
#define BYTES 36864u
#define RESET 0xfe83fffcu
#define SG_ADDRESS 0xfe802040u
#define SG_MAX 0xfe8020d4u
#define MARKER 0xfe830400u
#define TOKEN 0x005a34c1u
#define MAGIC 0x47504f31u
#define FAIL(stage) (0xdf200000u|(stage))
typedef u32 (__attribute__((stdcall)) *Physical)(void *);
typedef unsigned char (__attribute__((stdcall)) *Valid)(void *);
typedef u32 (__attribute__((stdcall)) *Query)(void *);
typedef u64 (__attribute__((stdcall)) *Counter)(void);

static __attribute__((always_inline)) inline u32 quiet(u32 reset) {
    return WORD(RESET)==reset && WORD(0xfe801004u)==0xafau &&
           WORD(0xfe802000u)==7u && WORD(0xfe801100u)==0x71f8fu &&
           WORD(0xfe801000u)==0u && WORD(0xfd6806a0u)==0x11u &&
           WORD(SG_ADDRESS)==GP_MARKER_PHYSICAL && WORD(SG_MAX)==1544u;
}
static __attribute__((always_inline)) inline u32 expected(u32 index) {
    /* Conditional assignments keep these constants in the extracted .text;
     * a compiler-generated absolute switch table is not a valid EXEC image.
     */
    u32 value=0x87u;
    if(index==0u)value=0x65f400u;
    if(index==1u)value=0xfcu;
    if(index==2u)value=0x44f400u;
    if(index==3u)value=TOKEN;
    if(index==4u)value=0x021584u;
    return value;
}

u32 gp_marker_probe(void) {
    _Static_assert(GP_MARKER_PHASE>=0 && GP_MARKER_PHASE<=2,"closed phase");
    _Static_assert(GP_MARKER_PHYSICAL!=0u && !(GP_MARKER_PHYSICAL&16383u) &&
                   GP_MARKER_PHYSICAL<=0x04000000u-BYTES,"exact16KiB owned base");
    _Static_assert(GP_MARKER_ORIGINAL_SG!=0u && !(GP_MARKER_ORIGINAL_SG&16383u) &&
                   GP_MARKER_ORIGINAL_SG<=0x03ffc000u &&
                   GP_MARKER_ORIGINAL_SG!=GP_MARKER_PHYSICAL,"provenance source");
#if GP_MARKER_PHASE != 0
    _Static_assert(!(GP_MARKER_INITIAL&0xff000000u) && GP_MARKER_INITIAL!=TOKEN,
                   "exact preflight marker differs from token");
#endif
    const u32 reset=GP_MARKER_PHASE==2 ? 3u : 0u;
    if(!quiet(reset))return FAIL(1u);
    Physical physical=(Physical)kernel_export(173u);
    Valid valid=(Valid)kernel_export(174u);
    Query protect=(Query)kernel_export(179u),extent=(Query)kernel_export(180u);
    Counter clock=(Counter)kernel_export(126u),frequency=(Counter)kernel_export(127u);
    if(!physical || !valid || !protect || !extent || !clock || !frequency ||
       frequency()!=3375000ull)return FAIL(2u);
    if(valid((void *)0x80010000u)!=1u || valid((void *)0x40000000u)!=0u ||
       physical((void *)0x80010000u)!=0x10000u)return FAIL(3u);
    u64 beginning=clock();
    volatile u32 *owned=(volatile u32 *)(0x80000000u|GP_MARKER_PHYSICAL);
    /* Verify actual retained mappings/protection before ANY owned RAM load. */
    for(u32 i=0u;i<9u;++i) {
        void *first=(void *)(owned+i*1024u),*last=(void *)((u32)first+4095u);
        if(valid(first)!=1u || valid(last)!=1u)return FAIL(4u);
        if(physical(first)!=GP_MARKER_PHYSICAL+i*4096u ||
           physical(last)!=GP_MARKER_PHYSICAL+i*4096u+4095u)return FAIL(5u);
        if(protect(first)!=0x204u || protect(last)!=0x204u)return FAIL(6u);
    }
    if(extent((void *)owned)!=BYTES)return FAIL(7u);
    volatile u32 *header=owned+8192u;
    if(header[0]!=MAGIC || header[1]!=GP_MARKER_PHYSICAL ||
       header[2]!=GP_MARKER_ORIGINAL_SG ||
       header[3]!=(MAGIC^GP_MARKER_PHYSICAL^GP_MARKER_ORIGINAL_SG))return FAIL(8u);
    for(u32 i=0u;i<2048u;++i) {
        const u32 page=GP_MARKER_PHYSICAL+(i<4u ? (i+4u)*4096u : 7u*4096u);
        if(owned[i*2u]!=page || owned[i*2u+1u]!=0u)return FAIL(9u);
    }
    volatile u32 *image=owned+4096u;
    for(u32 i=0u;i<4096u;++i)if(image[i]!=expected(i))return FAIL(10u);
    /* Require an advancing, bounded kernel counter BEFORE any reset write.
     * This time source bounds the probe; it says nothing about MCPX B3.
     */
    u64 now=beginning;
    for(u32 i=0u;i<64u && now==beginning;++i)now=clock();
    if(now<=beginning || now-beginning>3375000ull)return FAIL(11u);
    if(!quiet(reset))return FAIL(12u);
#if GP_MARKER_PHASE == 0
    const u32 marker=WORD(MARKER);
    if((marker&0xff000000u) || marker==TOKEN)return FAIL(13u);
    return marker;
#elif GP_MARKER_PHASE == 1
    if(WORD(MARKER)!=GP_MARKER_INITIAL)return FAIL(13u);
    /* The separate operation ends at its immediate raw reset readback.
     * Unexpected readback never triggers clock/marker/P reads or recovery.
     */
    WORD(RESET)=3u;
    return WORD(RESET);
#else
    const u64 origin=now;
    u64 previous=origin;
    u32 polls;
    for(polls=1u;polls<=100000u;++polls) {
        const u32 marker=WORD(MARKER);
        if(marker==TOKEN)break;
        if(marker!=GP_MARKER_INITIAL && marker!=0u)return FAIL(14u);
        now=clock();
        if(now<previous)return FAIL(15u);
        previous=now;
        if(now-origin>=168750ull)return FAIL(16u);
    }
    if(polls>100000u)return FAIL(17u);
    /* A CPU write never creates the marker. Verify every word of the actual
     * reference8KiB bootstrap extent, rather than only its first instruction.
     */
    for(u32 i=0u;i<2048u;++i) {
        if(WORD(0xfe83a000u+i*4u)!=expected(i))return 0xdf210000u|i;
        if(!(i&63u)) {
            now=clock();
            if(now<previous)return FAIL(15u);
            previous=now;
            if(now-origin>=168750ull)return FAIL(16u);
        }
    }
    if(!quiet(3u) || WORD(MARKER)!=TOKEN)return FAIL(18u);
    return 0xd5000000u|polls;
#endif
}
