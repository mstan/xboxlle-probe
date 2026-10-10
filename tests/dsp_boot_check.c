/* Offline execution of actual generated boot image with the pinned MIT DSP CPU.
 * No Xbox or original firmware; caller supplies only a generated test image.
 */
#include "dsp56300.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t p[4096],x[4096],y[2048];
static uint32_t denied_read(void *opaque,uint32_t address) {
    (void)opaque;fprintf(stderr,"unexpected DSP peripheral read %06x\n",address);exit(2);
}
static void denied_write(void *opaque,uint32_t address,uint32_t value) {
    (void)opaque;(void)value;fprintf(stderr,"unexpected DSP peripheral write %06x\n",address);exit(2);
}
#define BUFFER(first,last,data) {first,last,DSP56300_REGION_BUFFER,{.buffer={data,0}}}
#define GUARD(first) {first,0x1000000,DSP56300_REGION_CALLBACK,{.callback={NULL,denied_read,denied_write}}}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    FILE *input=fopen(argv[1],"rb");if(!input)return 2;
    if(fread(p,1,sizeof(p),input)!=sizeof(p) || fgetc(input)!=EOF)return 2;
    fclose(input);
    for(unsigned i=0;i<4096;++i)x[i]=0x100000u+i;
    for(unsigned i=0;i<2048;++i)y[i]=0x200000u+i;
    Dsp56300MemoryRegion pr[]={BUFFER(0,4096,p),GUARD(4096)};
    Dsp56300MemoryRegion xr[]={BUFFER(0,4096,x),GUARD(4096)};
    Dsp56300MemoryRegion yr[]={BUFFER(0,2048,y),GUARD(2048)};
    Dsp56300CreateInfo info={.memory_map={xr,2,yr,2,pr,2}};
    Dsp56300Jit *dsp=dsp56300_create(&info);if(!dsp)return 2;
    dsp56300_run(dsp,1000);
    Dsp56300State state;dsp56300_get_state(dsp,&state);
    if(state.pc!=6 || state.power_state!=2 || state.registers[DSP56300_REG_SP]!=0)return 1;
    for(unsigned i=0;i<4096;++i)if(x[i]!=(i==0x100?0x5a34c1u:0x100000u+i))return 1;
    for(unsigned i=0;i<2048;++i)if(y[i]!=0x200000u+i)return 1;
    dsp56300_destroy(dsp);
    puts("PASS: actual generated DSP code writes only X100 marker, then STOP; no peripheral access");return 0;
}
