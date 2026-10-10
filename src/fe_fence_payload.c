/* Closed 32-bit EXEC probe. No upload, storage, GPIO, DSP or GPU operation.
 * The one independently allocated uncached page is NEVER freed: a timed-out
 * device may write it late. This bounds lifetime safely until console restart.
 * Original helper's ordering is evidence to test, not asserted semantics.
 */
#include "payload_kernel32.h"
#define FE_CONTROL 0xfe801510u
#define FE_ADDRESS 0xfe801324u
#define FE_DATA 0xfe801334u
#define TOKEN 0x5a34f00eu
#define INITIAL 0xa5cb0ff1u
#define LIMIT 100000u
#ifndef FE_OBSERVE_HELD
#define FE_OBSERVE_HELD 0
#endif

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
    u32 early=0u,invalid_held=0u;
#if FE_OBSERVE_HELD
    /* Distinct follow-up experiment: actual RAM reads while bit0 is still 1.
     * Positive visibility proves this bit is not an absolute idle-data gate;
     * absence across a finite sample is not proof of permanent blocking.
     */
    u32 held_before=WORD(FE_CONTROL),held=INITIAL;
    for (u32 i=0u;i<1000u;++i) {
        held=scratch[0];
        if (held!=INITIAL) break;
    }
    early=held==TOKEN ? 0x00800000u : 0u;
    u32 held_after=WORD(FE_CONTROL);
    invalid_held=(held!=INITIAL && held!=TOKEN) || held_before!=1u || held_after!=1u;
#endif
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
    if (last!=TOKEN || polls>LIMIT || invalid_held) return 0xf2000000u | (polls&0x1ffffu);
    return 0xf1000000u | early | polls;
}
