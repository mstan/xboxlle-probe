/* Offline input model only, never linked into the target capture object. */
#include "noise_pair_mock.h"
typedef uint32_t DWORD;
#define VIDEO_BASE 0xfd000000u
#define NV_USER 0x800000u
#define NV_PFB_WC_CACHE 0x100410u
#define NV_PFB_WC_CACHE_FLUSH_TRIGGER 0x10000u
#define NV_PFB_WC_CACHE_FLUSH_IN_PROGRESS 0x10000u
#define NV_PGRAPH_STATUS 0x400700u
#define NV_PGRAPH_NSOURCE 0x400108u
#define NV_PGRAPH_RDI_INDEX 0x400750u
#define NV_PGRAPH_RDI_DATA 0x400754u
#define VIDEOREG(offset) (*(volatile uint32_t *)(VIDEO_BASE+(offset)))
int model_fault;
static int pb_noise_initialized=1,pb_running=1,pb_disable_gpu;
static unsigned pb_FifoChannelID,pb_FifoChannelsReady=1;
static uint32_t *pb_Head=(uint32_t *)0x81200000,*pb_Put=(uint32_t *)0x81200000;
static uint32_t *pb_Tail=(uint32_t *)0x81240000;
static volatile DWORD *pb_DmaUserAddr=(DWORD *)0xfd800000;
static unsigned pb_FrameBuffersWidth=640,pb_FrameBuffersHeight=480;
static unsigned pb_FrameBuffersPitch=2560,pb_GPUFrameBuffersFormat=0x128,pb_FBVFlag;
static uint32_t pb_FBAddr[3]={0x81300000,0,0};
static unsigned pb_back_index;
unsigned model_allocations,model_locks;
static unsigned long long counter;

void *MmAllocateContiguousMemoryEx(uint32_t n,uint32_t lo,uint32_t hi,uint32_t align,uint32_t protect) {
    ++model_allocations;
    if(n!=4096 || lo || hi!=0x03ffafff || align!=4096 ||
       protect!=(model_allocations==1?0x204u:0x404u)) return 0;
    if(model_fault==1 && model_allocations==1) return 0;
    if(model_fault==2 && model_allocations==2) return 0;
    return (void *)(uintptr_t)(model_allocations==1?0x81000000u:0x81001000u);
}
uint32_t MmIsAddressValid(void *p) {return (uintptr_t)p>=0x81000000 && (uintptr_t)p<0x81002000;}
uint32_t MmQueryAllocationSize(void *p) {(void)p;return 4096;}
uint32_t MmQueryAddressProtect(void *p) {
    if(model_fault==3)return 4;
    return (uintptr_t)p<0x81001000?0x204:0x404;
}
uintptr_t MmGetPhysicalAddress(void *p) {
    if(model_fault==7 && (uintptr_t)p>=0x81000000 && (uintptr_t)p<0x81001000)
        return 0x01300000u+((uintptr_t)p&4095u);
    if(model_fault==8 && (uintptr_t)p>=0x81001000 && (uintptr_t)p<0x81002000)
        return 0x01000000u+((uintptr_t)p&4095u);
    return (uintptr_t)p&0x1fffffff;
}
void MmLockUnlockBufferPages(void *p,uint32_t n,int unlock) {(void)p;(void)n;(void)unlock;++model_locks;}
unsigned long long KeQueryPerformanceFrequency(void) {return 3375000;}
unsigned long long KeQueryPerformanceCounter(void) {return model_fault==4?0:(++counter)*1000;}
#include "../src/noise_pair_pbkit.inc"
uint32_t model_prepare(int fault) {
    model_fault=fault;
    if(fault==5)pb_noise_initialized=0;
    if(fault==6)pb_Tail=pb_Put+16;
    return 0;
}
