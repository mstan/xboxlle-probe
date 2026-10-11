/* Offline-reviewed ownership/calibration stages. Never starts either DSP.
 * No inherited SG RAM load, descriptor DMA, FIFO, FE/IRQ or storage write.
 * Every allocated/pinned page is retained until an ordinary console restart.
 */
#include "payload_kernel32.h"
#ifndef GP_OWNED_MODE
#define GP_OWNED_MODE 0
#endif
#ifndef GP_OWNED_PHYSICAL
#define GP_OWNED_PHYSICAL 0u
#endif
#ifndef GP_OWNED_ORIGINAL_SG
#define GP_OWNED_ORIGINAL_SG 0u
#endif
#define BYTES 36864u
/* Original GP/EP SG allocators request16KiB table alignment. A physical
 * observation clearedbit13 of a4KiB-only request; the complete silicon mask
 * remains unqualified. Exact readback is still required before DSP use. */
#define TABLE_ALIGNMENT 16384u
#define RESET 0xfe83fffcu
#define SG_ADDRESS 0xfe802040u
#define SG_MAX 0xfe8020d4u
#define MAGIC 0x47504f31u
#define TOKEN 0x005a34c1u
typedef void *(__attribute__((stdcall)) *Allocate)(u32,u32,u32,u32,u32);
typedef u32 (__attribute__((stdcall)) *Physical)(void *);
typedef unsigned char (__attribute__((stdcall)) *Valid)(void *);
typedef u32 (__attribute__((stdcall)) *Protect)(void *);
typedef u32 (__attribute__((stdcall)) *Extent)(void *);
typedef void (__attribute__((stdcall)) *Pin)(void *,u32,unsigned char);

static __attribute__((always_inline)) inline u32 quiet(void) {
    return WORD(RESET)==0u && WORD(0xfe801004u)==0xafau &&
           WORD(0xfe802000u)==7u && WORD(0xfe801100u)==0x71f8fu &&
           WORD(0xfe801000u)==0u && WORD(0xfd6806a0u)==0x11u;
}

u32 gp_owned_probe(void) {
    if(!quiet()) return 0xdf100001u;
    u32 original=WORD(SG_ADDRESS), maximum=WORD(SG_MAX);
    if(!original || (original&(TABLE_ALIGNMENT-1u)) || original>0x03fff000u || maximum!=1544u)
        return 0xdf100002u;
    Physical physical=(Physical)kernel_export(173u);
    Valid valid=(Valid)kernel_export(174u);
    Protect protect=(Protect)kernel_export(179u);
    Extent extent=(Extent)kernel_export(180u);
    if(!physical || !valid || !protect || !extent) return 0xdf100003u;
    /* BOOLEAN is AL, not the undefined upper EAX bits. Never reverse it. */
    if(valid((void *)0x80010000u)!=1u || valid((void *)0x40000000u)!=0u ||
       physical((void *)0x80010000u)!=0x10000u) return 0xdf100004u;
    volatile u32 *owned;
    u32 address;
#if GP_OWNED_MODE == 0
    Allocate allocate=(Allocate)kernel_export(166u);
    Pin pin=(Pin)kernel_export(175u);
    if(!allocate || !pin) return 0xdf100003u;
    owned=allocate(BYTES,0u,0x03ffffffu,TABLE_ALIGNMENT,0x204u);
    if(!owned) return 0xdf100005u;
    /* Validate allocator-returned memory before Physical or any RAM access. */
    if(valid((void *)owned)!=1u) return 0xdf100006u;
    address=physical((void *)owned);
    if(!address || (address&(TABLE_ALIGNMENT-1u)) || address>0x04000000u-BYTES ||
       (u32)owned!=(0x80000000u|address) || original==address)
        return 0xdf100007u;
#else
    _Static_assert(GP_OWNED_MODE==1 || GP_OWNED_MODE==2,"closed ownership phase");
    _Static_assert(GP_OWNED_PHYSICAL!=0u && !(GP_OWNED_PHYSICAL&(TABLE_ALIGNMENT-1u)) &&
                   GP_OWNED_PHYSICAL<=0x04000000u-BYTES,"bounded owned address");
    address=GP_OWNED_PHYSICAL;
    owned=(volatile u32 *)(0x80000000u|address);
#endif
    /* Probe only mappings for this fresh preparation's returned allocation.
     * No inherited SG pointer is translated or dereferenced. Check both ends
     * of every page and every physical/protection result before loading RAM.
     */
    for(u32 i=0u;i<BYTES/4096u;++i) {
        void *first=(void *)(owned+i*1024u), *last=(void *)((u32)first+4095u);
        if(valid(first)!=1u || valid(last)!=1u) return 0xdf100008u;
        if(physical(first)!=address+i*4096u || physical(last)!=address+i*4096u+4095u)
            return 0xdf100009u;
        if(protect(first)!=0x204u || protect(last)!=0x204u) return 0xdf10000au;
    }
    if(extent((void *)owned)!=BYTES) return 0xdf10000bu;
#if GP_OWNED_MODE == 0
    pin((void *)owned,BYTES,0u);
    /* Lock is a void API: require fresh post-lock mapping/protection evidence. */
    for(u32 i=0u;i<BYTES/4096u;++i) {
        void *first=(void *)(owned+i*1024u), *last=(void *)((u32)first+4095u);
        if(valid(first)!=1u || valid(last)!=1u ||
           physical(first)!=address+i*4096u || physical(last)!=address+i*4096u+4095u ||
           protect(first)!=0x204u || protect(last)!=0x204u) return 0xdf10000cu;
    }
    /* Four table pages cover all1545 inherited-max entries without accessing
     * their inherited backing. Four input P pages are STOP-filled; no DSP runs.
     * Page8 is an owned provenance header, never an SGE target.
     */
    for(u32 i=0u;i<BYTES/4u;++i) owned[i]=0x87u;
    for(u32 i=0u;i<2048u;++i) {
        owned[i*2u]=address+(i<4u ? (i+4u)*4096u : 7u*4096u);
        owned[i*2u+1u]=0u;
    }
    volatile u32 *boot=owned+4096u;
    boot[0]=0x65f400u; boot[1]=0xfcu; boot[2]=0x44f400u;
    boot[3]=TOKEN; boot[4]=0x021584u; boot[5]=0x87u;
    volatile u32 *header=owned+8192u;
    header[0]=MAGIC; header[1]=address; header[2]=original;
    header[3]=address^original^MAGIC;
#else
    volatile u32 *header=owned+8192u;
    if(header[0]!=MAGIC || header[1]!=address || header[2]!=original ||
       header[3]!=(address^original^MAGIC)) return 0xdf10000du;
#endif
    for(u32 i=0u;i<2048u;++i) {
        u32 expected=address+(i<4u ? (i+4u)*4096u : 7u*4096u);
        if(owned[i*2u]!=expected || owned[i*2u+1u]!=0u) return 0xdf10000eu;
    }
    volatile u32 *image=owned+4096u;
    for(u32 i=0u;i<4096u;++i) {
        u32 expected=0x87u;
        if(i==0u) expected=0x65f400u;
        if(i==1u) expected=0xfcu;
        if(i==2u) expected=0x44f400u;
        if(i==3u) expected=TOKEN;
        if(i==4u) expected=0x021584u;
        if(image[i]!=expected) return 0xdf10000fu;
    }
    if(!quiet() || WORD(SG_ADDRESS)!=original || WORD(SG_MAX)!=maximum)
        return 0xdf100010u;
#if GP_OWNED_MODE == 0
    /* The tag leaves ALL26 physical-address bits free for lossless recovery. */
    return 0xd4000000u|address;
#elif GP_OWNED_MODE == 1
    return original;
#else
    _Static_assert(GP_OWNED_ORIGINAL_SG!=0u && !(GP_OWNED_ORIGINAL_SG&(TABLE_ALIGNMENT-1u)) &&
                   GP_OWNED_ORIGINAL_SG<=0x03fff000u,"exact original SG context");
    if(original!=GP_OWNED_ORIGINAL_SG || original==address) return 0xdf100011u;
    /* Exactly one device write followed by its immediate raw DWORD readback.
     * The host already knows the requested address. No subsequent MMIO,
     * recovery store, free/unlock, clock poll or RAM write follows the read.
     * ANY mismatch ends the experiment; owner inspects before another request.
     */
    WORD(SG_ADDRESS)=address;
    return WORD(SG_ADDRESS);
#endif
}
