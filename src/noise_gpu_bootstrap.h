/* SPDX-License-Identifier: MIT
 * Closed diagnostic owner. Not used by the default agent or stock SDK.
 */
#ifndef XLLE_NOISE_GPU_BOOTSTRAP_H
#define XLLE_NOISE_GPU_BOOTSTRAP_H
#include <stdint.h>
#include <xboxkrnl/xboxkrnl.h>

typedef struct {
    uint32_t magic, version, status, phase, entered, irq_connected, pending;
    uint32_t retained, last_address, requested, observed, reads, writes;
    uint32_t sdk_result, capture_result, services, polls, irq_calls;
    uint32_t current_thread, stack_limit, stack_base, event_handle;
    uint32_t last_effect_written, last_observed_valid;
    struct { uint32_t address, size, physical, protection; } allocations[12];
} NoiseGpuBootstrapResult;
__declspec(dllexport) extern volatile NoiseGpuBootstrapResult noise_gpu_bootstrap_result;

__declspec(dllexport) int noise_gpu_bootstrap(void);
__declspec(dllexport) int noise_gpu_capture(void);
void noise_boot_poll(void);
__attribute__((noreturn)) void noise_boot_abort(unsigned why);
void noise_boot_debug_stop(const char *format, ...);
int noise_boot_irq_connect(void);
void noise_boot_dpc_ready(void);
void noise_boot_bus_master(void);
void noise_boot_pci_setup(void);
void noise_boot_wbinvd(void);
PVOID NTAPI noise_boot_allocate(SIZE_T, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG);
PVOID NTAPI noise_boot_instance(SIZE_T, SIZE_T *);
NTSTATUS NTAPI noise_boot_event(PHANDLE, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN);
void noise_boot_memcpy(void *, const void *, unsigned);
void noise_boot_memset(void *, unsigned char, unsigned);
void *noise_boot_sdk_memset(void *, int, unsigned);
void *noise_boot_sdk_memcpy(void *, const void *, unsigned);

#define NOISE_ACCESS(T,N) T noise_boot_load_##N(const T *); \
                         void noise_boot_store_##N(T *, T)
NOISE_ACCESS(uint8_t,i8);
NOISE_ACCESS(uint16_t,i16);
NOISE_ACCESS(uint32_t,i32);
NOISE_ACCESS(uint64_t,i64);
NOISE_ACCESS(float,f32);
NOISE_ACCESS(double,f64);
void *noise_boot_load_ptr(void *const *);
void noise_boot_store_ptr(void **, void *);
#undef NOISE_ACCESS
#endif
