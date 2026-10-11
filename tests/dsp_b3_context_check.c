/* Authored finite B3 diagnostic program check on the pinned DSP CPU.
 * Injected sample values validate instruction/ownership routes only, never
 * MCPX counter frequency, configuration identity or physical bootstrap.
 */
#include "dsp56300.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t p[4096],before[4096],x[4096],y[2048];
static unsigned configured,sampled;
static const uint32_t sample[3]={17,1009,5521};
static uint32_t read_context(void *opaque,uint32_t address) {
    (void)opaque;
    if(address!=0xffffb3 || configured!=3 || sampled>=3) exit(2);
    return sample[sampled++];
}
static void write_context(void *opaque,uint32_t address,uint32_t value) {
    (void)opaque;
    const uint32_t addresses[3]={0xffffb2,0xffffb0,0xffffb1};
    const uint32_t values[3]={0xffffff,1,1};
    if(configured>=3 || sampled || address!=addresses[configured] || value!=values[configured])exit(2);
    ++configured;
}
static uint32_t denied_read(void *opaque,uint32_t address) {
    (void)opaque;(void)address;exit(2);
}
static void denied_write(void *opaque,uint32_t address,uint32_t value) {
    (void)opaque;(void)address;(void)value;exit(2);
}
#define BUFFER(first,last,data) {first,last,DSP56300_REGION_BUFFER,{.buffer={data,0}}}
#define CALLBACK(first,last,reader,writer) {first,last,DSP56300_REGION_CALLBACK,{.callback={NULL,reader,writer}}}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    FILE *f=fopen(argv[1],"rb");if(!f)return 2;
    if(fread(p,1,sizeof(p),f)!=sizeof(p) || fgetc(f)!=EOF)return 2;
    fclose(f);memcpy(before,p,sizeof(p));
    for(unsigned i=0;i<4096;++i)x[i]=0x100000+i;
    for(unsigned i=0;i<2048;++i)y[i]=0x200000+i;
    Dsp56300MemoryRegion pr[]={BUFFER(0,4096,p),CALLBACK(4096,0x1000000,denied_read,denied_write)};
    Dsp56300MemoryRegion xr[]={BUFFER(0,4096,x),CALLBACK(4096,0xffffb0,denied_read,denied_write),
        CALLBACK(0xffffb0,0xffffb4,read_context,write_context),
        CALLBACK(0xffffb4,0x1000000,denied_read,denied_write)};
    Dsp56300MemoryRegion yr[]={BUFFER(0,2048,y),CALLBACK(2048,0x1000000,denied_read,denied_write)};
    Dsp56300CreateInfo info={.memory_map={xr,4,yr,2,pr,2}};
    Dsp56300Jit *dsp=dsp56300_create(&info);if(!dsp)return 2;
    dsp56300_run(dsp,1000);
    Dsp56300State state;dsp56300_get_state(dsp,&state);
    if(state.pc!=103 || state.power_state!=2 || state.registers[DSP56300_REG_SP]!=0 ||
       configured!=3 || sampled!=3 || memcmp(p,before,sizeof(p)))return 1;
    for(unsigned i=0;i<4096;++i) {
        uint32_t expected=0x100000+i;
        if(i>=0x100 && i<=0x102) expected=sample[i-0x100];
        if(i==0x104) expected=0x5a34c1;
        if(x[i]!=expected)return 1;
    }
    for(unsigned i=0;i<2048;++i)if(y[i]!=0x200000+i)return 1;
    dsp56300_destroy(dsp);
    puts("PASS: exact3 configuration writes,3 injected B3 samples,4 owned X targets and STOP; no DMA/frame/output");
    return 0;
}
