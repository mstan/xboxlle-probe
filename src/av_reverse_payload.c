/* One distinct reverse-direction AV observation. No mode/timing programming,
 * kernel call, clock/frequency inference, restoring request or automatic retry.
 * The existing AV_HANDSHAKE command/latch is neither called nor reset.
 */
typedef unsigned int u32;
#define WORD(address) (*(volatile u32 *)(address))
#define AV 0xfd6806a0u

u32 av_reverse_probe(void) {
    /* Exact context from preceding successful probes. No reset assumption. */
    if (WORD(0xfd680848u)!=0x10100111u || WORD(0xfd680824u)!=935u ||
        WORD(0xfd680804u)!=524u || WORD(0xfd680834u)!=0u)
        return 0xe4000000u;
    if (WORD(AV)!=0u || WORD(AV)!=0u) return 0xe4000001u;
    WORD(AV)=1u;
    u32 first=0u;
    for (u32 polls=1u;polls<=100000u;++polls) {
        u32 value=WORD(AV);
        if (polls==1u) first=((value&1u)|((value>>3)&2u))<<17;
        if (value!=1u && value!=0x11u) return 0xe3000000u | first | polls;
        if (value==0x11u) return 0xe1000000u | first | polls;
    }
    return 0xe2000000u | first | 100000u;
}
