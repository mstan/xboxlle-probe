#ifndef NOISE_PAIR_MOCK_H
#define NOISE_PAIR_MOCK_H
#include <stdint.h>
#include <stddef.h>
#define FALSE 0
void *MmAllocateContiguousMemoryEx(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
uint32_t MmIsAddressValid(void *);
uint32_t MmQueryAllocationSize(void *);
uint32_t MmQueryAddressProtect(void *);
uintptr_t MmGetPhysicalAddress(void *);
void MmLockUnlockBufferPages(void *,uint32_t,int);
unsigned long long KeQueryPerformanceFrequency(void);
unsigned long long KeQueryPerformanceCounter(void);
#endif
