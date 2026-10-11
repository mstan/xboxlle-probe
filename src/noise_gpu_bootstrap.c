/* SPDX-License-Identifier: MIT
 * A real exclusive IRQ and finite foreground owner for a separate diagnostic.
 * No teardown, fallback, disk I/O, automatic startup or external ready setter.
 * The closed MMIO policy deliberately guards unsupported bootstrap effects.
 */
#include "noise_gpu_bootstrap.h"
_Static_assert(sizeof(NoiseGpuBootstrapResult)==288,"fixed retained result layout");

__declspec(dllexport) volatile NoiseGpuBootstrapResult noise_gpu_bootstrap_result = {
    .magic=0x4e474231, .version=1
};
static KINTERRUPT noise_interrupt;
static void *noise_unwind[5];
static int noise_active, noise_servicing, noise_dpc_ready;
static uint64_t noise_frequency, noise_previous, noise_deadline;
static int noise_instance_queried;
static int noise_zero_owned;
static int noise_timer_preparing;
static unsigned noise_timer_stage;
static uint32_t noise_timer_div,noise_timer_mul,noise_timer_pll;
/* Existing framebuffer, timer, scanout and graphics ownership must be active.
 * This diagnostic enables PFIFO without resetting any active engine. Unknown
 * or variant-dependent enable fields retain their actual observed value.
 */
#define NOISE_EXISTING_ENGINES 0x01111000u
#define NOISE_REQUIRED_ENGINES 0x00001100u
extern int pb_init(void);
extern int noise_pair_capture(void);
extern void noise_sdk_service(void);

static void noise_record_failure(unsigned why) {
    if(!noise_gpu_bootstrap_result.status) noise_gpu_bootstrap_result.status=why;
}
static void noise_check_sticky(void) {
    if(noise_gpu_bootstrap_result.status) noise_boot_abort(noise_gpu_bootstrap_result.status);
}
static BOOLEAN noise_valid(void *p) {
    BOOLEAN result=MmIsAddressValid(p); noise_check_sticky(); return result;
}
static uint32_t noise_physical(void *p) {
    uint32_t result=(uint32_t)MmGetPhysicalAddress(p); noise_check_sticky(); return result;
}
static ULONG noise_protect(void *p) {
    ULONG result=MmQueryAddressProtect(p); noise_check_sticky(); return result;
}
static SIZE_T noise_size(void *p) {
    SIZE_T result=MmQueryAllocationSize(p); noise_check_sticky(); return result;
}
__attribute__((noreturn)) void noise_boot_abort(unsigned why) {
    noise_record_failure(why);
    if(noise_active) __builtin_longjmp(noise_unwind,1);
    /* There is no safe command frame to return to in an undeclared invocation. */
    __builtin_trap();
}
void noise_boot_debug_stop(const char *format, ...) {
    (void)format; noise_boot_abort(30); /* no SDK error UI or infinite Sleep loop */
}
static uint32_t noise_cli(void) {
    uint32_t flags;
    __asm__ __volatile__("pushfl; popl %0; cli" : "=r"(flags) :: "memory");
    return flags;
}
static void noise_flags(uint32_t flags) {
    __asm__ __volatile__("pushl %0; popfl" :: "r"(flags) : "memory");
}
static uint32_t noise_raw_read(uint32_t address) {
    ++noise_gpu_bootstrap_result.reads;
    return *(volatile uint32_t *)(uintptr_t)address;
}
static void noise_raw_store(uint32_t address,uint32_t value) {
    noise_gpu_bootstrap_result.last_address=address;
    noise_gpu_bootstrap_result.requested=value;
    noise_gpu_bootstrap_result.last_effect_written=1;
    noise_gpu_bootstrap_result.last_observed_valid=0;
    ++noise_gpu_bootstrap_result.writes;
    *(volatile uint32_t *)(uintptr_t)address=value;
}
static BOOLEAN NTAPI noise_isr(PKINTERRUPT interrupt,PVOID context) {
    (void)context;
    ++noise_gpu_bootstrap_result.irq_calls;
    /* KeConnectInterrupt itself supplies this object to the real callback. */
    if(interrupt!=&noise_interrupt || noise_gpu_bootstrap_result.status) return FALSE;
    uint32_t status=noise_raw_read(0xfd000100);
    if(!status) return FALSE;
    noise_raw_store(0xfd000140,0);
    uint32_t observed=noise_raw_read(0xfd000140);
    noise_gpu_bootstrap_result.observed=observed;
    noise_gpu_bootstrap_result.last_observed_valid=1;
    if(observed) { noise_record_failure(12); return TRUE; }
    noise_gpu_bootstrap_result.pending=1;
    return TRUE;
}
int noise_boot_irq_connect(void) {
    if(noise_gpu_bootstrap_result.status) noise_boot_abort(11);
    if(noise_gpu_bootstrap_result.irq_connected) return 1; /* actual same owner */
    KIRQL irql; ULONG vector=HalGetInterruptVector(3,&irql);
    if(!vector || !irql) noise_boot_abort(10);
    KeInitializeInterrupt(&noise_interrupt,noise_isr,NULL,vector,irql,LevelSensitive,FALSE);
    if(!KeConnectInterrupt(&noise_interrupt)) noise_boot_abort(11);
    noise_gpu_bootstrap_result.irq_connected=1;
    /* Only the actual exclusive connection admits the first hardware store. */
    noise_boot_store_i32((uint32_t *)0xfd000140,0);
    return 1;
}
void noise_boot_dpc_ready(void) { noise_dpc_ready=1; }
void noise_boot_poll(void) {
    if(!noise_active) noise_boot_abort(1);
    if(noise_gpu_bootstrap_result.status) noise_boot_abort(noise_gpu_bootstrap_result.status);
    unsigned polls=++noise_gpu_bootstrap_result.polls;
    if(polls>=1000000u) noise_boot_abort(8);
    if(!(polls&63)) {
        uint64_t now=KeQueryPerformanceCounter();
        noise_check_sticky(); /* an ISR may have failed during the kernel call */
        if(now<noise_previous) noise_boot_abort(7);
        noise_previous=now;
        if(now>=noise_deadline) noise_boot_abort(8);
    }
    if(noise_gpu_bootstrap_result.pending && noise_dpc_ready && !noise_servicing) {
        uint32_t flags=noise_cli();
        noise_gpu_bootstrap_result.pending=0;
        noise_servicing=1;
        noise_flags(flags);
        ++noise_gpu_bootstrap_result.services;
        noise_sdk_service(); /* actual compiled SDK handler, no queued DPC */
        noise_servicing=0;
    }
}
static int noise_mmio(uintptr_t address,unsigned bytes) {
    return address>=0xfd000000u && address<0xfe000000u &&
           address+bytes>=address && address+bytes<=0xfe000000u;
}
static int noise_vga_byte(uintptr_t address) {
    /* Primary NV3:G80 PRMVIO, PRMCIO and PRMDIO byte-register aliases.
     * No whole-window exemption, second-head assumption or PRMFB admission.
     */
    switch(address) {
    case 0xfd0c03c2: case 0xfd0c03c3: case 0xfd0c03c4: case 0xfd0c03c5:
    case 0xfd0c03cc: case 0xfd0c03ce: case 0xfd0c03cf:
    case 0xfd6013b4: case 0xfd6013b5: case 0xfd6013ba: case 0xfd6013c0:
    case 0xfd6013c1: case 0xfd6013c2: case 0xfd6013ca:
    case 0xfd6013d4: case 0xfd6013d5: case 0xfd6013da:
    case 0xfd6813c6: case 0xfd6813c7: case 0xfd6813c8: case 0xfd6813c9:
        return 1;
    default:return 0;
    }
}
static int noise_mmio_width(uintptr_t address,unsigned bytes) {
    if(bytes==1) return noise_vga_byte(address);
    if(bytes!=4 || (address&3)) return 0;
    /* A DWORD crossing defined VGA byte registers is not an ordinary register. */
    for(unsigned i=0;i<4;++i) if(noise_vga_byte(address+i)) return 0;
    return 1;
}
static void noise_cpu_store_guard(uintptr_t address,unsigned bytes) {
    if(address<0x80000000u) return; /* the diagnostic image's ordinary globals */
    if(address>=noise_gpu_bootstrap_result.stack_limit && address+bytes>=address &&
       address+bytes<=noise_gpu_bootstrap_result.stack_base) return;
    if(noise_zero_owned && address==0x80000000u && bytes==4) return;
    for(unsigned i=0;i<noise_gpu_bootstrap_result.retained;++i) {
        uint32_t begin=noise_gpu_bootstrap_result.allocations[i].address;
        uint32_t end=begin+noise_gpu_bootstrap_result.allocations[i].size;
        if(address>=begin && address+bytes>=address && address+bytes<=end) return;
    }
    noise_gpu_bootstrap_result.last_address=(uint32_t)address;
    noise_boot_abort(21);
}
static uint32_t noise_read_mmio(uintptr_t address,unsigned bytes) {
    noise_boot_poll();
    if(!noise_gpu_bootstrap_result.irq_connected || !noise_mmio_width(address,bytes)) {
        noise_gpu_bootstrap_result.last_address=(uint32_t)address;
        noise_gpu_bootstrap_result.last_effect_written=0;
        noise_gpu_bootstrap_result.last_observed_valid=0;
        noise_boot_abort(13);
    }
    uint32_t flags=noise_cli();
    if(noise_gpu_bootstrap_result.status) { noise_flags(flags); noise_boot_abort(12); }
    ++noise_gpu_bootstrap_result.reads;
    uint32_t value=bytes==1?*(volatile uint8_t *)address:
                   bytes==2?*(volatile uint16_t *)address:*(volatile uint32_t *)address;
    noise_flags(flags);
    return value;
}
static void noise_store_mmio(uintptr_t address,uint32_t value,unsigned bytes) {
    noise_boot_poll();
    noise_gpu_bootstrap_result.last_address=(uint32_t)address;
    noise_gpu_bootstrap_result.requested=value;
    noise_gpu_bootstrap_result.last_effect_written=0;
    noise_gpu_bootstrap_result.last_observed_valid=0;
    if(!noise_gpu_bootstrap_result.irq_connected || !noise_mmio_width(address,bytes)) noise_boot_abort(13);
    /* Closed ordinary enable fields. Any other effect stops BEFORE the store.
     * PBUS aliases use aligned DWORD accesses, as required by primary BAR0 docs.
     * PCI command writes zero to STATUS; MISC preserves HEADER_TYPE/BIST.
     * ROM decode clears only ENABLE and must preserve its observed address.
     * PMC_ENABLE admits only the documented PFIFO/PGRAPH OR policy below.
     * SDK reset/clock/PIO/scanout effects require separate review.
     */
    uint32_t mask=0;
    if(bytes==4 && address==0xfd000140 && value<=1) mask=3;
    if(bytes==4 && (address==0xfd600140 || address==0xfd009140) && value==0) mask=1;
    if(bytes==4 && address==0xfd001804 && !(value&0xffff0000u)) mask=0xffff;
    if(bytes==4 && address==0xfd001830 && !(value&1)) mask=0xffffffffu;
    if(bytes==4 && address==0xfd00180c && (value&0xffff)==0xf800) mask=0xffffffffu;
    if(bytes==4 && address==0xfd000200) mask=0xffffffffu;
    if(bytes==4 && noise_timer_preparing) {
        if(address==0xfd009200 && !noise_timer_stage && (value&0xffff)==56968) mask=0xffff;
        if(address==0xfd009210 && noise_timer_stage==1 && (value&0xffff)==7629) mask=0xffff;
        if(address==0xfd009420 && noise_timer_stage==2 && value==0xffffffffu) mask=0xffffffe0u;
    }
    if(!mask) noise_boot_abort(14);
    uint32_t flags=noise_cli();
    if(noise_gpu_bootstrap_result.status) { noise_flags(flags); noise_boot_abort(12); }
    if(address==0xfd000200) {
        uint32_t before=noise_raw_read((uint32_t)address);
        if((before&NOISE_EXISTING_ENGINES)!=NOISE_EXISTING_ENGINES ||
           value!=(before|NOISE_REQUIRED_ENGINES) ||
           noise_raw_read(0xfd000140) || noise_raw_read(0xfd600140) ||
           noise_raw_read(0xfd009140) || noise_raw_read(0xfd000100) ||
           noise_raw_read(0xfd400700) || noise_raw_read(0xfd400108) ||
           ((before&0x100) && noise_raw_read(0xfd002100)) ||
           noise_raw_read((uint32_t)address)!=before) {
            noise_flags(flags); noise_boot_abort(32);
        }
    }
    if(address==0xfd009200 || address==0xfd009210 || address==0xfd009420) {
        if(noise_raw_read(0xfd009140) || noise_raw_read(0xfd000140)!=1 ||
           noise_raw_read(0xfd000100) ||
           noise_raw_read(0xfd680500)!=noise_timer_pll ||
           noise_raw_read(0xfd009200)!=noise_timer_div ||
           noise_raw_read(0xfd009210)!=noise_timer_mul ||
           (address==0xfd009200 && value!=((noise_timer_div&~0xffffu)|56968)) ||
           (address==0xfd009210 && value!=((noise_timer_mul&~0xffffu)|7629))) {
            noise_flags(flags); noise_boot_abort(33);
        }
    }
    if(address==0xfd001804 || address==0xfd001830 || address==0xfd00180c) {
        /* No relocation, W1C acknowledgement, or BIST/header change is allowed.
         * Check the current full value inside the same checked transaction.
         */
        ++noise_gpu_bootstrap_result.reads;
        uint32_t before=*(volatile uint32_t *)address;
        uint32_t expected=address==0xfd001804?((before&0xffff)|4):
                          address==0xfd001830?(before&~1u):((before&~0xffffu)|0xf800);
        if(value!=expected || (address==0xfd00180c && (before&0x407f0000u))) {
            noise_flags(flags); noise_boot_abort(14);
        }
    }
    ++noise_gpu_bootstrap_result.writes;
    noise_gpu_bootstrap_result.last_effect_written=1;
    if(bytes==1) *(volatile uint8_t *)address=(uint8_t)value;
    else if(bytes==2) *(volatile uint16_t *)address=(uint16_t)value;
    else *(volatile uint32_t *)address=value;
    ++noise_gpu_bootstrap_result.reads;
    uint32_t observed=bytes==1?*(volatile uint8_t *)address:
                      bytes==2?*(volatile uint16_t *)address:*(volatile uint32_t *)address;
    noise_gpu_bootstrap_result.observed=observed;
    noise_gpu_bootstrap_result.last_observed_valid=1;
    if((observed&mask)!=(value&mask)) noise_record_failure(12);
    /* Unspecified ratio bits are preserved, never declared inert. */
    if((address==0xfd009200 || address==0xfd009210) && observed!=value) noise_record_failure(12);
    if(address==0xfd009420 && (observed&31)) noise_record_failure(12);
    noise_flags(flags);
    if(noise_gpu_bootstrap_result.status) noise_boot_abort(12);
    if(address==0xfd009200) { noise_timer_div=observed; ++noise_timer_stage; }
    if(address==0xfd009210) { noise_timer_mul=observed; ++noise_timer_stage; }
    if(address==0xfd009420) ++noise_timer_stage;
    if(address==0xfd000200) {
        /* A successful enable is not a ready certificate or a completion.
         * No pending source is acknowledged or hidden to advance startup.
         */
        if(noise_boot_load_i32((uint32_t *)0xfd000100) ||
           noise_boot_load_i32((uint32_t *)0xfd400700) ||
           noise_boot_load_i32((uint32_t *)0xfd400108) ||
           noise_boot_load_i32((uint32_t *)0xfd002100)) noise_boot_abort(32);
    }
}
#define INTEGER_ACCESS(T,N) \
T noise_boot_load_##N(const T *p) { noise_boot_poll(); \
    return noise_mmio((uintptr_t)p,sizeof(T))?(T)noise_read_mmio((uintptr_t)p,sizeof(T)):*p; } \
void noise_boot_store_##N(T *p,T v) { noise_boot_poll(); \
    if(noise_mmio((uintptr_t)p,sizeof(T))) noise_store_mmio((uintptr_t)p,v,sizeof(T)); \
    else { noise_cpu_store_guard((uintptr_t)p,sizeof(T)); *p=v; } }
INTEGER_ACCESS(uint8_t,i8)
INTEGER_ACCESS(uint16_t,i16)
INTEGER_ACCESS(uint32_t,i32)
#undef INTEGER_ACCESS
#define ATOMIC_ACCESS(T,N) \
T noise_boot_load_acquire_##N(const T *p) { noise_boot_poll(); \
    return noise_mmio((uintptr_t)p,sizeof(T))?(T)noise_read_mmio((uintptr_t)p,sizeof(T)):\
           __atomic_load_n(p,__ATOMIC_ACQUIRE); } \
void noise_boot_store_release_##N(T *p,T v) { noise_boot_poll(); \
    if(noise_mmio((uintptr_t)p,sizeof(T))) noise_store_mmio((uintptr_t)p,v,sizeof(T)); \
    else { noise_cpu_store_guard((uintptr_t)p,sizeof(T)); __atomic_store_n(p,v,__ATOMIC_RELEASE); } }
ATOMIC_ACCESS(uint8_t,i8)
ATOMIC_ACCESS(uint16_t,i16)
ATOMIC_ACCESS(uint32_t,i32)
#undef ATOMIC_ACCESS
#define RAM_ACCESS(T,N) \
T noise_boot_load_##N(const T *p) { noise_boot_poll(); \
    if(noise_mmio((uintptr_t)p,sizeof(T))) noise_boot_abort(13); return *p; } \
void noise_boot_store_##N(T *p,T v) { noise_boot_poll(); \
    if(noise_mmio((uintptr_t)p,sizeof(T))) noise_boot_abort(13); \
    noise_cpu_store_guard((uintptr_t)p,sizeof(T)); *p=v; }
RAM_ACCESS(uint64_t,i64)
RAM_ACCESS(_Bool,b1)
RAM_ACCESS(float,f32)
RAM_ACCESS(double,f64)
#undef RAM_ACCESS
void *noise_boot_load_ptr(void *const *p) { return (void *)(uintptr_t)noise_boot_load_i32((const uint32_t *)p); }
void noise_boot_store_ptr(void **p,void *v) { noise_boot_store_i32((uint32_t *)p,(uint32_t)(uintptr_t)v); }
void noise_boot_memset(void *p,unsigned char v,unsigned n) {
    for(unsigned i=0;i<n;++i) noise_boot_store_i8((uint8_t *)p+i,v);
}
void noise_boot_memcpy(void *p,const void *q,unsigned n) {
    for(unsigned i=0;i<n;++i) noise_boot_store_i8((uint8_t *)p+i,noise_boot_load_i8((const uint8_t *)q+i));
}
void *noise_boot_sdk_memset(void *p,int value,unsigned n) {
    noise_boot_poll();
    if(!n) return p;
    uintptr_t address=(uintptr_t)p;
    if(address+n<address || noise_mmio(address,n)) noise_boot_abort(13);
    noise_cpu_store_guard(address,n);
    for(unsigned i=0;i<n;++i) {
        if(!(i&4095)) noise_boot_poll();
        ((uint8_t *)p)[i]=(uint8_t)value;
    }
    return p;
}
void *noise_boot_sdk_memcpy(void *p,const void *q,unsigned n) {
    noise_boot_poll();
    if(!n) return p;
    uintptr_t address=(uintptr_t)p,source=(uintptr_t)q;
    if(address+n<address || source+n<source || noise_mmio(address,n) || noise_mmio(source,n))
        noise_boot_abort(13);
    noise_cpu_store_guard(address,n);
    for(unsigned i=0;i<n;++i) {
        if(!(i&4095)) noise_boot_poll();
        ((uint8_t *)p)[i]=((const uint8_t *)q)[i];
    }
    return p;
}
void noise_boot_bus_master(void) {
    uint32_t old=noise_boot_load_i32((uint32_t *)0xfd001804);
    /* Zero STATUS does not acknowledge any of its W1C flags. */
    noise_boot_store_i32((uint32_t *)0xfd001804,(old&0xffff)|4);
}
void noise_boot_pci_setup(void) {
    /* Type-zero PCI header only. An active BIST is not our bootstrap owner.
     * Aligned DWORD write preserves HEADER_TYPE and the inactive BIST fields.
     */
    uint32_t misc=noise_boot_load_i32((uint32_t *)0xfd00180c);
    if((misc&0x007f0000u) || (misc&0x40000000u)) {
        noise_gpu_bootstrap_result.last_address=0xfd00180c;
        noise_gpu_bootstrap_result.requested=0;
        noise_gpu_bootstrap_result.observed=misc;
        noise_gpu_bootstrap_result.last_effect_written=0;
        noise_gpu_bootstrap_result.last_observed_valid=1;
        noise_boot_abort(31);
    }
    uint32_t rom=noise_boot_load_i32((uint32_t *)0xfd001830);
    noise_boot_store_i32((uint32_t *)0xfd001830,rom&~1u);
    noise_boot_store_i32((uint32_t *)0xfd00180c,(misc&~0xffffu)|0xf800);
}
void noise_boot_engine_setup(void) {
    uint32_t enabled=noise_boot_load_i32((uint32_t *)0xfd000200);
    noise_boot_store_i32((uint32_t *)0xfd000200,enabled|NOISE_REQUIRED_ENGINES);
}
void noise_boot_timer_setup(void) {
    if(noise_timer_preparing || noise_timer_stage || noise_frequency!=3375000u) noise_boot_abort(33);
    noise_timer_pll=noise_boot_load_i32((uint32_t *)0xfd680500);
    uint32_t m=noise_timer_pll&255,n=(noise_timer_pll>>8)&255,p=(noise_timer_pll>>16)&7;
    if(!m || ((16666666u*n)/(1u<<p))/m!=233333324u) noise_boot_abort(33);
    noise_timer_div=noise_boot_load_i32((uint32_t *)0xfd009200);
    noise_timer_mul=noise_boot_load_i32((uint32_t *)0xfd009210);
    uint32_t div=noise_timer_div&0xffff,mul=noise_timer_mul&0xffff;
    /* Both the existing and intermediate ratio must be defined. Zero MUL is
     * a stopped counter, allowed here; this command's ACPI deadline is separate.
     */
    if(!div || mul>div || mul>56968) noise_boot_abort(33);
    noise_timer_preparing=1;
    noise_boot_store_i32((uint32_t *)0xfd009200,(noise_timer_div&~0xffffu)|56968);
    noise_boot_store_i32((uint32_t *)0xfd009210,(noise_timer_mul&~0xffffu)|7629);
    noise_boot_store_i32((uint32_t *)0xfd009420,0xffffffffu);
    uint32_t pending=noise_boot_load_i32((uint32_t *)0xfd009100);
    if(pending&~1u) noise_boot_abort(33);
    /* A real ALARM can be pending while masked; do not acknowledge it or
     * manufacture ready/completion. PMC must still have no asserted source.
     */
    if(noise_boot_load_i32((uint32_t *)0xfd009140) ||
       noise_boot_load_i32((uint32_t *)0xfd000100)) noise_boot_abort(33);
    noise_timer_preparing=0;
}
void noise_boot_wbinvd(void) {
    noise_boot_poll();
    if(!noise_zero_owned) noise_boot_abort(22);
    __asm__ __volatile__("wbinvd" ::: "memory");
}
static void noise_check_allocation(uint32_t address,uint32_t size,uint32_t physical,uint32_t protect) {
    if((address&4095) || !physical || (physical&4095) ||
       physical>0x03ffb000u-size || address+size<address ||
       noise_size((void *)(uintptr_t)address)<size) noise_boot_abort(20);
    noise_check_sticky();
    for(uint32_t offset=0;offset<size;offset+=4096) {
        void *page=(void *)(uintptr_t)(address+offset);
        BOOLEAN valid=noise_valid(page);
        if(!valid) noise_boot_abort(20);
        ULONG protection=noise_protect(page);
        if(protection!=protect) noise_boot_abort(20);
        ULONG observed=noise_physical(page);
        if(observed!=physical+offset) noise_boot_abort(20);
    }
    ULONG last=noise_physical((void *)(uintptr_t)(address+size-1));
    noise_check_sticky(); if(last!=physical+size-1) noise_boot_abort(20);
}
PVOID NTAPI noise_boot_allocate(SIZE_T bytes,ULONG_PTR low,ULONG_PTR high,ULONG_PTR align,ULONG protect) {
    noise_boot_poll();
    if(!bytes || bytes>0x400000 || low || high>0x03ffffff ||
       (align && align!=0x4000) ||
       (protect!=PAGE_READWRITE && protect!=(PAGE_READWRITE|PAGE_WRITECOMBINE)) ||
       noise_gpu_bootstrap_result.retained>=12) noise_boot_abort(19);
    uint32_t size=(bytes+4095)&~4095u;
    if(!align) align=4096;
    if(high>0x03ffafff) high=0x03ffafff;
    void *p=MmAllocateContiguousMemoryEx(size,4096,high,align,protect);
    if(!p) noise_boot_abort(19);
    unsigned index=noise_gpu_bootstrap_result.retained++;
    uint32_t address=(uint32_t)(uintptr_t)p;
    noise_gpu_bootstrap_result.allocations[index].address=address;
    noise_gpu_bootstrap_result.allocations[index].size=size;
    noise_gpu_bootstrap_result.allocations[index].protection=protect;
    noise_check_sticky(); /* retain a returned allocation before any further API */
    uint32_t physical=noise_physical(p);
    noise_gpu_bootstrap_result.allocations[index].physical=physical;
    if(physical&(align-1)) noise_boot_abort(20);
    noise_check_allocation(address,size,physical,protect);
    for(unsigned i=0;i<index;++i) {
        uint32_t before=noise_gpu_bootstrap_result.allocations[i].physical;
        uint32_t end=before+noise_gpu_bootstrap_result.allocations[i].size;
        if(physical<end && physical+size>before) noise_boot_abort(20);
    }
    MmLockUnlockBufferPages(p,size,FALSE);
    noise_check_sticky();
    noise_check_allocation(address,size,physical,protect);
    return p;
}
PVOID NTAPI noise_boot_instance(SIZE_T request,SIZE_T *padding) {
    noise_boot_poll();
    if(request!=0xffffffffu || noise_instance_queried) noise_boot_abort(23);
    void *top=MmClaimGpuInstanceMemory(request,padding); /* query, not resize */
    noise_check_sticky();
    uint32_t address=(uint32_t)(uintptr_t)top;
    if(!top || !padding || *padding<0x5000 || *padding>0x10000 ||
       (address&4095) || address<0x80005000 || address>0x83ff0000) noise_boot_abort(23);
    uint32_t start=address-0x5000,physical=noise_physical((void *)(uintptr_t)start);
    noise_check_sticky();
    for(uint32_t offset=0;offset<0x5000;offset+=4096) {
        void *page=(void *)(uintptr_t)(start+offset);
        BOOLEAN valid=noise_valid(page);
        if(!valid) noise_boot_abort(23);
        ULONG protection=noise_protect(page);
        if((protection&0xff)!=PAGE_READWRITE) noise_boot_abort(23);
        ULONG observed=noise_physical(page);
        if(observed!=physical+offset) noise_boot_abort(23);
    }
    if(physical!=start-0x80000000 || physical+0x5000>0x03ff0000) noise_boot_abort(23);
    MmLockUnlockBufferPages((void *)(uintptr_t)start,0x5000,FALSE);
    noise_check_sticky();
    for(uint32_t offset=0;offset<0x5000;offset+=4096) {
        void *page=(void *)(uintptr_t)(start+offset);
        if(!noise_valid(page) || (noise_protect(page)&0xff)!=PAGE_READWRITE ||
           noise_physical(page)!=physical+offset) noise_boot_abort(23);
    }
    if(noise_physical((void *)(uintptr_t)(address-1))!=physical+0x4fff) noise_boot_abort(23);
    /* CPU reservation provenance does not establish a physical PRAMIN alias.
     * All aperture writes stay guarded pending that independent owner proof.
     */
    noise_instance_queried=1;
    return top;
}
NTSTATUS NTAPI noise_boot_event(PHANDLE handle,POBJECT_ATTRIBUTES attributes,EVENT_TYPE type,BOOLEAN state) {
    noise_boot_poll();
    NTSTATUS result=NtCreateEvent(handle,attributes,type,state);
    noise_gpu_bootstrap_result.event_handle=(uint32_t)(uintptr_t)*handle;
    noise_check_sticky();
    if(result || !*handle) noise_boot_abort(24);
    return result;
}
static void noise_verify_stack(void) {
    PKTHREAD thread=KeGetCurrentThread();
    noise_check_sticky();
    if(!thread || !noise_valid(thread) ||
       !noise_valid((char *)thread+sizeof(*thread)-1)) noise_boot_abort(4);
    uint32_t limit=(uint32_t)(uintptr_t)thread->StackLimit;
    uint32_t base=(uint32_t)(uintptr_t)thread->StackBase,stack;
    __asm__ __volatile__("movl %%esp,%0" : "=r"(stack));
    if((limit&4095) || (base&4095) || base<=limit || base-limit>0x100000 ||
       stack<limit || stack>=base || !noise_valid((void *)(uintptr_t)limit) ||
       !noise_valid((void *)(uintptr_t)(base-1))) noise_boot_abort(4);
    noise_gpu_bootstrap_result.current_thread=(uint32_t)(uintptr_t)thread;
    noise_gpu_bootstrap_result.stack_limit=limit;
    noise_gpu_bootstrap_result.stack_base=base;
}
static void noise_preflight(void) {
    noise_frequency=KeQueryPerformanceFrequency();
    uint64_t first=KeQueryPerformanceCounter(),now=first;
    /* Captured original kernel exports126/127 use board port8008, independent
     * of PTIMER, and return exactly3375000Hz. No TSC or other-kernel inference.
     */
    if(noise_frequency!=3375000u) noise_boot_abort(6);
    for(unsigned i=0;i<4096 && now==first;++i) now=KeQueryPerformanceCounter();
    if(now<=first) noise_boot_abort(7);
    noise_previous=now; noise_deadline=now+noise_frequency*2;
    if(noise_deadline<=now) noise_boot_abort(7);
    noise_verify_stack();
    /* Original reserved bootstrap page, NEVER an allocation or free target. */
    if(!noise_valid((void *)0x80000000) ||
       noise_physical((void *)0x80000000)!=0 ||
       noise_physical((void *)0x80000fff)!=0xfff ||
       (noise_protect((void *)0x80000000)&0xff)!=PAGE_READWRITE) noise_boot_abort(22);
    noise_zero_owned=1;
    uint32_t enabled=noise_raw_read(0xfd000200);
    if((enabled&NOISE_EXISTING_ENGINES)!=NOISE_EXISTING_ENGINES) {
        noise_gpu_bootstrap_result.last_address=0xfd000200;
        noise_gpu_bootstrap_result.requested=NOISE_EXISTING_ENGINES;
        noise_gpu_bootstrap_result.observed=enabled;
        noise_gpu_bootstrap_result.last_observed_valid=1;
        noise_boot_abort(32);
    }
    if(noise_raw_read(0xfd400700) || noise_raw_read(0xfd400108) || noise_raw_read(0xfd000100))
        noise_boot_abort(9);
}
int noise_gpu_bootstrap(void) {
    if(__atomic_exchange_n(&noise_gpu_bootstrap_result.entered,1,__ATOMIC_ACQ_REL)) {
        unsigned status=noise_gpu_bootstrap_result.status;
        return status?(int)status:noise_gpu_bootstrap_result.phase==90?0:28;
    }
    __atomic_store_n(&noise_active,1,__ATOMIC_RELEASE);
    if(!__builtin_setjmp(noise_unwind)) {
        noise_gpu_bootstrap_result.phase=1;
        noise_preflight();
        noise_gpu_bootstrap_result.phase=2;
        noise_boot_irq_connect();
        noise_gpu_bootstrap_result.phase=3;
        int result=pb_init(); /* actual pinned, bounded SDK producer */
        noise_gpu_bootstrap_result.sdk_result=(uint32_t)result;
        if(result) noise_boot_abort(25);
        noise_gpu_bootstrap_result.phase=90;
    }
    __atomic_store_n(&noise_active,0,__ATOMIC_RELEASE);
    return (int)noise_gpu_bootstrap_result.status;
}
int noise_gpu_capture(void) {
    if(noise_gpu_bootstrap_result.phase!=90 || noise_gpu_bootstrap_result.status)
        return 26;
    if(__atomic_exchange_n(&noise_active,1,__ATOMIC_ACQ_REL)) return 28;
    if(!__builtin_setjmp(noise_unwind)) {
        noise_verify_stack(); /* each explicit command may run on a new client thread */
        uint64_t now=KeQueryPerformanceCounter(); noise_check_sticky();
        if(now<noise_previous) noise_boot_abort(7);
        noise_previous=now; noise_deadline=now+noise_frequency*2;
        if(noise_deadline<=now) noise_boot_abort(7);
        noise_gpu_bootstrap_result.capture_result=(uint32_t)noise_pair_capture();
        if(noise_gpu_bootstrap_result.capture_result) noise_boot_abort(27);
    }
    __atomic_store_n(&noise_active,0,__ATOMIC_RELEASE);
    return (int)noise_gpu_bootstrap_result.status;
}
