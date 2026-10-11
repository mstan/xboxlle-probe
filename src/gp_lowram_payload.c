/* Distinct low-RAM ownership/calibration prerequisite. No GP/EP start, DMA,
 * FIFO/output/IRQ/store to inherited RAM, retry, recovery or unlock/free.
 * Every validated allocation remains retained until an owner restart.
 */
#include "payload_kernel32.h"
#ifndef GP_LOWRAM_PHASE
#define GP_LOWRAM_PHASE 0
#endif
#ifndef GP_LOWRAM_PHYSICAL
#define GP_LOWRAM_PHYSICAL 0u
#endif
#ifndef GP_LOWRAM_ORIGINAL_SG
#define GP_LOWRAM_ORIGINAL_SG 0u
#endif
#define BYTES 36864u
#define ALIGNMENT 16384u
#define MAX_BASE 0x00600000u
/* HighestAcceptableAddress is the inclusive last byte, not the desired base.
 * The real allocation request owns all nine pages; no returned address is
 * rounded, truncated or substituted to manufacture low-RAM ownership.
 */
#define MAX_LAST (MAX_BASE+BYTES-1u)
#define RESET 0xfe83fffcu
#define SG_ADDRESS 0xfe802040u
#define SG_MAX 0xfe8020d4u
#define MAGIC 0x47504f31u
#define FAIL(stage) (0xdf300000u|(stage))
typedef void *(__attribute__((stdcall)) *Allocate)(u32,u32,u32,u32,u32);
typedef u32 (__attribute__((stdcall)) *Physical)(void *);
typedef unsigned char (__attribute__((stdcall)) *Valid)(void *);
typedef u32 (__attribute__((stdcall)) *Query)(void *);
typedef void (__attribute__((stdcall)) *Pin)(void *,u32,unsigned char);

static __attribute__((always_inline)) inline u32 quiet(void) {
    return WORD(RESET)==0u && WORD(0xfe801004u)==0xafau &&
           WORD(0xfe802000u)==7u && WORD(0xfe801100u)==0x71f8fu &&
           WORD(0xfe801000u)==0u && WORD(0xfd6806a0u)==0x11u;
}

u32 gp_lowram_probe(void) {
    _Static_assert(MAX_LAST==0x00608fffu,"inclusive full-allocation ceiling");
    _Static_assert(GP_LOWRAM_PHASE>=0 && GP_LOWRAM_PHASE<=2,"closed low-RAM phase");
    if(!quiet())return FAIL(1u);
    const u32 original=WORD(SG_ADDRESS),maximum=WORD(SG_MAX);
    if(!original || (original&(ALIGNMENT-1u)) || original>0x03ffc000u ||
       maximum!=1544u)return FAIL(2u);
    Physical physical=(Physical)kernel_export(173u);
    Valid valid=(Valid)kernel_export(174u);
    Query protect=(Query)kernel_export(179u),extent=(Query)kernel_export(180u);
    if(!physical || !valid || !protect || !extent)return FAIL(3u);
    if(valid((void *)0x80010000u)!=1u || valid((void *)0x40000000u)!=0u ||
       physical((void *)0x80010000u)!=0x10000u)return FAIL(4u);
    volatile u32 *owned;
    u32 address;
#if GP_LOWRAM_PHASE == 0
    Allocate allocate=(Allocate)kernel_export(166u);
    Pin pin=(Pin)kernel_export(175u);
    if(!allocate || !pin)return FAIL(3u);
    owned=allocate(BYTES,0u,MAX_LAST,ALIGNMENT,0x204u);
    /* A normal no-space failure causes no RAM access or later MMIO operation. */
    if(!owned)return FAIL(5u);
    if(valid((void *)owned)!=1u)return FAIL(6u);
    address=physical((void *)owned);
    if(!address || (address&(ALIGNMENT-1u)) || address>MAX_BASE ||
       (u32)owned!=(0x80000000u|address) || original==address)return FAIL(7u);
#else
    _Static_assert(GP_LOWRAM_PHYSICAL!=0u &&
                   !(GP_LOWRAM_PHYSICAL&(ALIGNMENT-1u)) &&
                   GP_LOWRAM_PHYSICAL<=MAX_BASE,"exact retained low-RAM base");
    address=GP_LOWRAM_PHYSICAL;
    owned=(volatile u32 *)(0x80000000u|address);
#endif
    /* Every mapping/protection/physical/extent result precedes owned loads. */
    for(u32 i=0u;i<9u;++i) {
        void *first=(void *)(owned+i*1024u),*last=(void *)((u32)first+4095u);
        if(valid(first)!=1u || valid(last)!=1u)return FAIL(8u);
        if(physical(first)!=address+i*4096u ||
           physical(last)!=address+i*4096u+4095u)return FAIL(9u);
        if(protect(first)!=0x204u || protect(last)!=0x204u)return FAIL(10u);
    }
    if(extent((void *)owned)!=BYTES)return FAIL(11u);
#if GP_LOWRAM_PHASE == 0
    pin((void *)owned,BYTES,0u);
    for(u32 i=0u;i<9u;++i) {
        void *first=(void *)(owned+i*1024u),*last=(void *)((u32)first+4095u);
        if(valid(first)!=1u || valid(last)!=1u ||
           physical(first)!=address+i*4096u ||
           physical(last)!=address+i*4096u+4095u ||
           protect(first)!=0x204u || protect(last)!=0x204u)return FAIL(12u);
    }
    for(u32 i=0u;i<BYTES/4u;++i)owned[i]=0x87u;
    for(u32 i=0u;i<2048u;++i) {
        owned[i*2u]=address+(i<4u ? (i+4u)*4096u : 7u*4096u);
        owned[i*2u+1u]=0u;
    }
    volatile u32 *image=owned+4096u;
    image[0]=0x65f400u;image[1]=0xfcu;image[2]=0x44f400u;
    image[3]=0x5a34c1u;image[4]=0x021584u;image[5]=0x87u;
    volatile u32 *header=owned+8192u;
    header[0]=MAGIC;header[1]=address;header[2]=original;
    header[3]=MAGIC^address^original;
#else
    volatile u32 *header=owned+8192u;
    if(header[0]!=MAGIC || header[1]!=address || header[2]!=original ||
       header[3]!=(MAGIC^address^original))return FAIL(13u);
    volatile u32 *image=owned+4096u;
#endif
    for(u32 i=0u;i<2048u;++i) {
        const u32 page=address+(i<4u ? (i+4u)*4096u : 7u*4096u);
        if(owned[i*2u]!=page || owned[i*2u+1u]!=0u)return FAIL(14u);
    }
    for(u32 i=0u;i<4096u;++i) {
        u32 expected=0x87u;
        if(i==0u)expected=0x65f400u;
        if(i==1u)expected=0xfcu;
        if(i==2u)expected=0x44f400u;
        if(i==3u)expected=0x5a34c1u;
        if(i==4u)expected=0x021584u;
        if(image[i]!=expected)return FAIL(15u);
    }
    if(!quiet() || WORD(SG_ADDRESS)!=original || WORD(SG_MAX)!=maximum)return FAIL(16u);
#if GP_LOWRAM_PHASE == 0
    return 0xd4000000u|address; /* Preserve all26 actual physical-address bits. */
#elif GP_LOWRAM_PHASE == 1
    return original;
#else
    _Static_assert(GP_LOWRAM_ORIGINAL_SG!=0u &&
                   !(GP_LOWRAM_ORIGINAL_SG&(ALIGNMENT-1u)) &&
                   GP_LOWRAM_ORIGINAL_SG<=0x03ffc000u &&
                   GP_LOWRAM_ORIGINAL_SG!=GP_LOWRAM_PHYSICAL,"exact original SG identity");
    if(original!=GP_LOWRAM_ORIGINAL_SG)return FAIL(17u);
    WORD(SG_ADDRESS)=address;
    return WORD(SG_ADDRESS); /* Immediate raw readback; no later operation. */
#endif
}
