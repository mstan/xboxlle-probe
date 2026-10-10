/* Read-only mapping query. No inherited SG RAM dereference or device store. */
#include "payload_kernel32.h"

u32 gp_mapping_probe(void) {
    typedef unsigned char (__attribute__((stdcall)) *Valid)(void *);
    typedef u32 (__attribute__((stdcall)) *Physical)(void *);
    Valid valid=(Valid)kernel_export(174u);
    Physical physical=(Physical)kernel_export(173u);
    if (!valid || !physical) return 0xde000001u;
    /* Calibrate the BOOLEAN convention before considering an inherited alias.
     * nxdk's comment contradicts its function name and agent-side usage.
     * Never reverse the interpretation or call Physical on an invalid page.
     */
    if (valid((void *)0x80010000u)!=1u || valid((void *)0x40000000u)!=0u)
        return 0xde000002u;
    if (physical((void *)0x80010000u)!=0x10000u) return 0xde000003u;
    u32 reset=WORD(0xfe83fffcu),av=WORD(0xfd6806a0u);
    u32 sg=WORD(0xfe802040u),maximum=WORD(0xfe8020d4u);
    if (reset!=0u || av!=0x11u || maximum!=1544u || !sg ||
        (sg&4095u) || sg>0x04000000u-16384u) return 0xde000004u;
    u32 mapped=0u,matching=0u;
    /* 1545 eight-byte SG entries occupy four pages. Query each mapping only;
     * no byte at these candidate virtual addresses is loaded by this payload.
     */
    for (u32 i=0u;i<4u;++i) {
        u32 candidate=0x80000000u| (sg+i*4096u);
        unsigned char present=valid((void *)candidate);
        if (present>1u) return 0xde000005u;
        if (present) {
            mapped|=1u<<i;
            if (physical((void *)candidate)==sg+i*4096u) matching|=1u<<i;
        }
    }
    if (WORD(0xfe83fffcu)!=reset || WORD(0xfd6806a0u)!=av ||
        WORD(0xfe802040u)!=sg || WORD(0xfe8020d4u)!=maximum) return 0xde000006u;
    return 0xd2000000u|mapped|(matching<<4);
}
