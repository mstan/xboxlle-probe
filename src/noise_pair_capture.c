/* Authored finite post-bootstrap diagnostic. No noise algorithm is presumed.
 * This module is NOT wired into the resident probe or automatically invoked.
 */
#include <stdint.h>
#ifdef NOISE_PAIR_MODEL
#include "../tests/noise_pair_mock.h"
#else
#include <xboxkrnl/xboxkrnl.h>
#endif
extern int pb_noise_owner(uint32_t **,uint32_t *,uint32_t *);
extern int pb_noise_control(uint32_t,uint32_t[2]);
extern int pb_noise_submit(const uint32_t *,uint32_t);

struct noise_pair_result {
    uint32_t magic,version,status,completed;
    uint32_t target_physical,target_pitch,texture_physical,snapshot_physical;
    uint32_t controls[4][3];
    uint32_t pixels[4][64];
};
struct noise_pair_result noise_pair_result;
static void *texture_owned,*snapshot_owned;
static uint32_t words[512],used;
static int entered;

static void emit(uint32_t method,uint32_t value) {
    words[used++]=0x40000u|method; words[used++]=value;
}
static uint32_t physical_page(void *address,uint32_t protection) {
    if(!address || ((uintptr_t)address&4095) || !MmIsAddressValid(address) ||
       !MmIsAddressValid((char *)address+4095) || MmQueryAllocationSize(address)<4096 ||
       MmQueryAddressProtect(address)!=protection) return 0;
    uint32_t physical=(uint32_t)MmGetPhysicalAddress(address);
    if(!physical || (physical&4095) || physical>0x03ffa000u ||
       MmGetPhysicalAddress((char *)address+4095)!=physical+4095) return 0;
    MmLockUnlockBufferPages(address,4096,FALSE);
    if(MmQueryAddressProtect(address)!=protection ||
       MmGetPhysicalAddress(address)!=physical) return 0;
    return physical;
}
static int submit(void) { return pb_noise_submit(words,used); }

/* Fixed authored MOV oPos=v0, MOV oT0=v1, nearest BC1, two screen-space
 * triangles covering8x8. Same literal inputs for all four observations. */
static void configure(uint32_t texture) {
    used=0;
    emit(0x200,8u<<16);emit(0x204,8u<<16);
    emit(0x290,0x00100001);emit(0x30c,0);emit(0x304,0);emit(0x300,0);
    emit(0x31c,0);emit(0x32c,0);emit(0x394,0);emit(0x1d78,0);
    emit(0x358,0x01010101);emit(0x2a4,0);emit(0x37c,0x1d01);
    emit(0x38c,0x1b02);emit(0x390,0x1b02);emit(0x1e94,2);
    emit(0x1e9c,0);emit(0x1ea0,0);emit(0x1e98,0);
    const uint32_t program[]={0,0x0020001b,0x08000000,0x0000f800,
                              0,0x0020021b,0x08000000,0x0000f849};
    for(unsigned i=0;i<8;++i) emit(0xb00+i*4,program[i]);
    for(unsigned i=0;i<4;++i) {emit(0xa20+i*4,0);emit(0xaf0+i*4,0x3f800000);}
    for(unsigned i=0;i<16;++i) emit(0x1760+i*4,0);
    emit(0x1760,0x42);emit(0x1764,0x42);
    emit(0x1e70,1);emit(0xac0,0x08200000);emit(0x260,0x18200000);
    emit(0x1e60,1);emit(0x1e40,0xc00);emit(0xaa0,0xc00);
    emit(0xaa4,0);emit(0xaa8,0);emit(0xaac,0);
    emit(0x288,0xc);emit(0x28c,0x1c00);
    emit(0x1b00,texture);emit(0x1b04,0x02210c29);emit(0x1b08,0x00030303);
    emit(0x1b0c,0x40000000);emit(0x1b14,0x01010000);
    for(unsigned i=1;i<4;++i) emit(0x1b0c+i*64,0);
}
static void draw(void) {
    used=0;emit(0x1d90,0xff102030);emit(0x1d98,7u<<16);
    emit(0x1d9c,7u<<16);emit(0x1d94,0xf0);emit(0x17fc,5);
    /* Six literal XY/UV pairs, eight float lanes per inline vertex. */
    const uint32_t v[6][4]={
        {0,0,0,0},{0x41000000,0,0x3f800000,0},{0,0x41000000,0,0x3f800000},
        {0,0x41000000,0,0x3f800000},{0x41000000,0,0x3f800000,0},
        {0x41000000,0x41000000,0x3f800000,0x3f800000}};
    for(unsigned i=0;i<6;++i) {
        emit(0x1818,v[i][0]);emit(0x1818,v[i][1]);emit(0x1818,0);emit(0x1818,0x3f800000);
        emit(0x1818,v[i][2]);emit(0x1818,v[i][3]);emit(0x1818,0);emit(0x1818,0x3f800000);
    }
    emit(0x17fc,0);
}
static void readback(uint32_t source,uint32_t pitch,uint32_t destination) {
    used=0;
    /* Owned SDK subchannel2 class39, full-RAM DMA objects3. No notify/IRQ. */
    emit(0x4000|0x184,3);emit(0x4000|0x188,3);
    emit(0x4000|0x30c,source);emit(0x4000|0x310,destination);
    emit(0x4000|0x314,pitch);emit(0x4000|0x318,32);
    emit(0x4000|0x31c,32);emit(0x4000|0x320,8);
    emit(0x4000|0x324,0x101);emit(0x4000|0x328,0);
}

uint32_t noise_pair_capture(void) {
    if(entered) return noise_pair_result.status?noise_pair_result.status:30;
    uint32_t *target,physical,pitch;
    int status=pb_noise_owner(&target,&physical,&pitch);
    if(status) return status; /* No allocation, stores or ready flag for absent owner. */
    entered=1;
    noise_pair_result.magic=0x4e504331;noise_pair_result.version=1;
    noise_pair_result.target_physical=physical;noise_pair_result.target_pitch=pitch;
    texture_owned=MmAllocateContiguousMemoryEx(4096,0,0x03ffafff,4096,0x204);
    uint32_t texture=physical_page(texture_owned,0x204);
    if(!texture || (texture<physical+pitch*480u && physical<texture+4096u))
        return noise_pair_result.status=31;
    snapshot_owned=MmAllocateContiguousMemoryEx(4096,0,0x03ffafff,4096,0x404);
    uint32_t snapshot=physical_page(snapshot_owned,0x404);
    if(!snapshot || snapshot==texture ||
       (snapshot<physical+pitch*480u && physical<snapshot+4096u))
        return noise_pair_result.status=32;
    noise_pair_result.texture_physical=texture;noise_pair_result.snapshot_physical=snapshot;
    /* Authored opaque BC1 block: RGB565 endpointsB571/2000, every selector
     * repeated in each row. This is a fixed microcase, not copied game art. */
    ((volatile uint32_t *)texture_owned)[0]=0x2000b571;
    ((volatile uint32_t *)texture_owned)[1]=0xe4e4e4e4;
    for(unsigned i=0;i<4096/4;++i) ((volatile uint32_t *)snapshot_owned)[i]=0xcccccccc;
    configure(texture);status=submit();if(status) return noise_pair_result.status=status;
    const uint32_t enables[4]={0,1,1,0};
    for(unsigned sample=0;sample<4;++sample) {
        noise_pair_result.controls[sample][0]=enables[sample];
        status=pb_noise_control(enables[sample],noise_pair_result.controls[sample]+1);
        if(status) return noise_pair_result.status=status;
        draw();status=submit();if(status) return noise_pair_result.status=status;
        readback(physical,pitch,snapshot+sample*256);
        status=submit();if(status) return noise_pair_result.status=status;
        for(unsigned pixel=0;pixel<64;++pixel)
            noise_pair_result.pixels[sample][pixel]=((volatile uint32_t *)snapshot_owned)[sample*64+pixel];
        noise_pair_result.completed=sample+1;
    }
    return 0;
}
