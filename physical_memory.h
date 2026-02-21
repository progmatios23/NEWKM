#pragma once
#include "definitions.h"
#include "spoof_call.h"

#define PTE_PRESENT      0x1ULL
#define PTE_LARGE_PAGE   0x80ULL
#define PTE_PHYS_MASK    0x0000FFFFFFFFF000ULL
#define PAGE_OFFSET_MASK 0xFFFULL

typedef struct _CR3_CACHE_ENTRY {
    volatile ULONG64 cr3;
    volatile HANDLE  pid;
    volatile ULONG   hits;
    volatile BOOLEAN locked;
} CR3_CACHE_ENTRY;

#define CR3_LOCK_THRESHOLD 500

NTSTATUS ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
VOID     InitCR3Cache();
BOOLEAN  ValidateCR3(ULONG64 cr3);
ULONG64  GetProcessCR3(HANDLE pid);
ULONG64  TranslateVirtualAddress(ULONG64 cr3, ULONG64 virtualAddress);
NTSTATUS PhysicalReadProcessMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size);
NTSTATUS PhysicalWriteProcessMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size);
