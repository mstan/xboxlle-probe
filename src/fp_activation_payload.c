/* Bounded one-pixel valid-window observation. Clock, sync, totals, enable,
 * GPIO, APU, EEPROM, flash and storage registers are never written.
 * Success restores HVALID_START=0, READ_PROG=1 and AV phase11.
 */
#include "payload_kernel32.h"
#ifndef FP_WAIT_WINDOW
#define FP_WAIT_WINDOW 0
#endif
#define CONTROL 0xfd680848u
#define WINDOW 0xfd680834u
#define AV 0xfd6806a0u
#define PROG 0x00100000u
#define EXPECTED 0x10100111u

#if FP_WAIT_WINDOW
typedef u64 (__attribute__((stdcall)) *Counter)(void);
static __attribute__((always_inline)) inline u32 wait_window(Counter clock) {
    u64 origin=clock(),previous=origin;
    for(u32 calls=0u;calls<2000000u;++calls) {
        u64 now=clock();
        if(now<previous) return 11u;
        previous=now;
        if(now-origin>=168750ull) return 0u;
    }
    return 12u;
}
#endif

static __attribute__((always_inline)) inline u32 active_window(void) {
    u32 original=WORD(CONTROL);
    if(original!=EXPECTED) return 0xffffffffu;
    WORD(CONTROL)=original&~PROG;
    u32 selected=WORD(CONTROL),value=0xffffffffu;
    if(selected==(EXPECTED&~PROG)) value=WORD(WINDOW);
    /* This is the planned read-selector restoration, not a retry. Preserve
     * fresh unrelated bits rather than reinstalling an old whole word.
     */
    u32 fresh=WORD(CONTROL);
    if(fresh!=(EXPECTED&~PROG)) return 0xffffffffu;
    WORD(CONTROL)=fresh|PROG;
    if(WORD(CONTROL)!=EXPECTED) return 0xffffffffu;
    return value;
}

static __attribute__((always_inline)) inline u32 transact(u32 request,u32 *pending) {
    WORD(AV)=request;
    for(u32 polls=1u;polls<=100000u;++polls) {
        u32 value=WORD(AV);
        if(value!=(request|((request^1u)<<4)) && value!=(request|(request<<4))) return 0u;
        if(value==(request|(request<<4))) return polls;
        *pending=1u;
    }
    return 0u;
}

u32 fp_activation_probe(void) {
    if(WORD(CONTROL)!=EXPECTED || WORD(0xfd680824u)!=935u ||
       WORD(0xfd680804u)!=524u || WORD(WINDOW)!=0u ||
       WORD(AV)!=0x11u || WORD(AV)!=0x11u) return 0xcf000001u;
#if FP_WAIT_WINDOW
    Counter clock=(Counter)kernel_export(126u),frequency=(Counter)kernel_export(127u);
    if(!clock || !frequency || frequency()!=3375000ull) return 0xcf00000au;
#endif
    if(active_window()!=0u) return 0xcf000002u;
    WORD(WINDOW)=1u;
    if(WORD(WINDOW)!=1u) return 0xcf000003u;
    u32 before=active_window();
    if(before>1u) return 0xcf000004u;
    u32 pending0=0u,pending1=0u;
    u32 polls0=transact(0u,&pending0);
    if(!polls0) return 0xcf000005u;
#if FP_WAIT_WINDOW
    u32 wait0=wait_window(clock);
    if(wait0) return 0xcf000000u|wait0;
#endif
    u32 after=active_window();
    if(after>1u) return 0xcf000006u;
    WORD(WINDOW)=0u;
    if(WORD(WINDOW)!=0u) return 0xcf000007u;
    u32 polls1=transact(1u,&pending1);
    if(!polls1) return 0xcf000008u;
#if FP_WAIT_WINDOW
    u32 wait1=wait_window(clock);
    if(wait1) return 0xcf000000u|wait1;
#endif
    if(active_window()!=0u) return 0xcf000009u;
    return 0xc1000000u | ((polls0+polls1)<<5) | before | (after<<1) |
           (pending0<<2) | (pending1<<3) | 16u;
}
