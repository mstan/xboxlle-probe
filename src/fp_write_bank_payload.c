/* Authored one-pixel write-bank observation. Only HVALID_START and the
 * existing READ_PROG selector are written. No AV request, clock, sync, total,
 * enable, GPIO, APU, EEPROM, flash or storage operation. Unexpected readback
 * returns immediately; success restores both observed windows and selector. */
#include "payload_kernel32.h"
#define CONTROL 0xfd680848u
#define WINDOW 0xfd680834u
#define AV 0xfd6806a0u
#define PROG 0x00100000u
#define EXPECTED 0x10100111u
#define FAIL(stage) (0xcf200000u | (stage))
u32 fp_write_bank_probe(void) {
    if (WORD(CONTROL)!=EXPECTED || WORD(0xfd680824u)!=935u ||
        WORD(0xfd680804u)!=524u || WORD(WINDOW)!=0u) return FAIL(1u);
    u32 phase=WORD(AV);
    if ((phase!=0u && phase!=0x11u) || WORD(AV)!=phase) return FAIL(2u);
    WORD(CONTROL)=EXPECTED&~PROG;
    if (WORD(CONTROL)!=(EXPECTED&~PROG) || WORD(WINDOW)!=0u) return FAIL(3u);
    WORD(WINDOW)=1u;
    u32 selected=WORD(WINDOW);
    if (selected>1u || WORD(CONTROL)!=(EXPECTED&~PROG)) return FAIL(4u);
    WORD(CONTROL)=EXPECTED;
    if (WORD(CONTROL)!=EXPECTED) return FAIL(5u);
    u32 programmed=WORD(WINDOW);
    if (programmed>1u) return FAIL(6u);
    WORD(WINDOW)=0u;
    if (WORD(WINDOW)!=0u || WORD(CONTROL)!=EXPECTED) return FAIL(7u);
    WORD(CONTROL)=EXPECTED&~PROG;
    if (WORD(CONTROL)!=(EXPECTED&~PROG)) return FAIL(8u);
    u32 after_program_restore=WORD(WINDOW);
    if (after_program_restore>1u) return FAIL(9u);
    WORD(WINDOW)=0u;
    if (WORD(WINDOW)!=0u || WORD(CONTROL)!=(EXPECTED&~PROG)) return FAIL(10u);
    WORD(CONTROL)=EXPECTED;
    if (WORD(CONTROL)!=EXPECTED || WORD(WINDOW)!=0u || WORD(AV)!=phase) return FAIL(11u);
    return 0xc2000080u | selected | (programmed<<1) |
        (after_program_restore<<2) | (phase==0x11u?8u:0u);
}
