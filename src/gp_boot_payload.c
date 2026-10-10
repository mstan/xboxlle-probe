/* Owned input-only GP bootstrap marker. No descriptor DMA, audio, FE/IRQ,
 * setup engine, FIFO, EP, GPU, GPIO, boot/storage/EEPROM/flash programming.
 * Entire SG/boot/sample/guard allocation remains owned until console restart.
 */
#include "payload_kernel32.h"
#define RESET 0xfe83fffcu
#define SG_ADDRESS 0xfe802040u
#define SG_MAX 0xfe8020d4u
#define MARKER 0xfe830400u
#define TOKEN 0x005a34c1u
#define BYTES 28672u

static __attribute__((always_inline)) inline u32 quiet(void) {
    return WORD(0xfe801004u)==0xafau && WORD(0xfe802000u)==7u &&
           WORD(0xfe801100u)==0x71f8fu && WORD(0xfe801000u)==0u &&
           WORD(0xfd6806a0u)==0x11u;
}

u32 gp_boot_probe(void) {
    typedef void *(__attribute__((stdcall)) *Allocate)(u32,u32,u32,u32,u32);
    typedef u32 (__attribute__((stdcall)) *Physical)(void *);
    typedef u64 (__attribute__((stdcall)) *Counter)(void);
    if(WORD(RESET)!=0u || !quiet()) return 0xdf000001u;
    u32 original_address=WORD(SG_ADDRESS),original_max=WORD(SG_MAX),original_marker=WORD(MARKER);
    if(!original_address || original_address>0x03fff000u || (original_address&4095u) ||
       original_max!=1544u || (original_marker&0xff000000u) || original_marker==TOKEN)
        return 0xdf000002u;
    Allocate allocate=(Allocate)kernel_export(166u);
    Physical physical=(Physical)kernel_export(173u);
    Counter clock=(Counter)kernel_export(126u),frequency=(Counter)kernel_export(127u);
    if(!allocate || !physical || !clock || !frequency || frequency()!=3375000ull)
        return 0xdf000003u;
    volatile u32 *owned=allocate(BYTES,0u,0x03ffffffu,4096u,0x204u);
    if(!owned) return 0xdf000004u;
    u32 address=physical((void *)owned);
    if(!address || address>0x04000000u-BYTES || (address&4095u) ||
       (u32)owned!=(0x80000000u|address)) return 0xdf000005u;
    /* Page0: all512 SG entries point into owned storage. Pages1..4: 16KB
     * P image (reference boot lead reads8KB). Page5: spare sample storage.
     * Page6: STOP-filled guard, also used for every unused SG entry.
     */
    for(u32 i=0u;i<BYTES/4u;++i) owned[i]=0x87u;
    for(u32 i=0u;i<512u;++i) {owned[i*2u]=address+24576u;owned[i*2u+1u]=0u;}
    for(u32 i=0u;i<6u;++i) owned[i*2u]=address+(i+1u)*4096u;
    volatile u32 *boot=owned+1024u;
    /* Authored MOVEs: R5=FC, X0=token, X:(R5+4)=X0, STOP. The CPU never
     * writes TOKEN to the observed DSP X marker, and performs no direct P write.
     */
    boot[0]=0x65f400u;boot[1]=0xfcu;boot[2]=0x44f400u;
    boot[3]=TOKEN;boot[4]=0x021584u;boot[5]=0x87u;
    for(u32 i=0u;i<512u;++i) {
        u32 expected=i<6u ? address+(i+1u)*4096u : address+24576u;
        if(owned[i*2u]!=expected || owned[i*2u+1u]!=0u) return 0xdf000006u;
    }
    if(boot[0]!=0x65f400u || boot[1]!=0xfcu || boot[2]!=0x44f400u ||
       boot[3]!=TOKEN || boot[4]!=0x021584u || boot[5]!=0x87u ||
       boot[2047]!=0x87u || boot[4095]!=0x87u) return 0xdf000006u;
    if(WORD(RESET)!=0u || !quiet() || WORD(SG_ADDRESS)!=original_address ||
       WORD(SG_MAX)!=original_max || WORD(MARKER)!=original_marker) return 0xdf000007u;
    WORD(SG_ADDRESS)=address;
    if(WORD(SG_ADDRESS)!=address) return 0xdf000008u;
    WORD(SG_MAX)=5u;
    if(WORD(SG_MAX)!=5u || WORD(RESET)!=0u || !quiet()) return 0xdf000009u;
    u64 origin=clock(),previous=origin;
    WORD(RESET)=3u;
    if(WORD(RESET)!=3u) return 0xdf00000au;
    u32 polls;
    for(polls=1u;polls<=100000u;++polls) {
        u32 marker=WORD(MARKER);
        if(marker==TOKEN) break;
        /* A boot ROM may clear X before loading P; admit zero as an observed
         * intermediate, without claiming its meaning or manufacturing it.
         */
        if(marker!=original_marker && marker!=0u) return 0xdf00000bu;
        u64 now=clock();
        if(now<previous) return 0xdf00000cu;
        previous=now;
        if(now-origin>=168750ull) return 0xdf00000du;
    }
    if(polls>100000u) return 0xdf00000eu;
    /* Marker establishes execution of supplied P code. Verify actual loaded
     * prefix and final word of the reference 8KB boot extent before stopping.
     */
    if(WORD(0xfe83a000u)!=0x65f400u || WORD(0xfe83a004u)!=0xfcu ||
       WORD(0xfe83a008u)!=0x44f400u || WORD(0xfe83a00cu)!=TOKEN ||
       WORD(0xfe83a010u)!=0x021584u || WORD(0xfe83a014u)!=0x87u ||
       WORD(0xfe83bffcu)!=0x87u || WORD(RESET)!=3u || !quiet() ||
       WORD(SG_ADDRESS)!=address || WORD(SG_MAX)!=5u) return 0xdf00000fu;
    WORD(RESET)=0u;
    if(WORD(RESET)!=0u || !quiet() || WORD(MARKER)!=TOKEN) return 0xdf000010u;
    WORD(MARKER)=original_marker;
    if(WORD(MARKER)!=original_marker) return 0xdf000011u;
    if(WORD(SG_ADDRESS)!=address || WORD(SG_MAX)!=5u) return 0xdf000012u;
    WORD(SG_MAX)=original_max;
    if(WORD(SG_MAX)!=original_max) return 0xdf000013u;
    WORD(SG_ADDRESS)=original_address;
    if(WORD(SG_ADDRESS)!=original_address || WORD(RESET)!=0u || !quiet())
        return 0xdf000014u;
    return 0xd1000000u|polls;
}
