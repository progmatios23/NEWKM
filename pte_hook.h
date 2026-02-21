#pragma once
#include "definitions.h"

typedef union _PTE_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 Owner : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 LargePage : 1;
        ULONG64 Global : 1;
        ULONG64 CopyOnWrite : 1;
        ULONG64 Prototype : 1;
        ULONG64 Reserved : 1;
        ULONG64 PageFrameNumber : 36;
        ULONG64 ReservedHigh : 4;
        ULONG64 SoftwareWsIndex : 11;
        ULONG64 NoExecute : 1;
    };
} PTE_ENTRY, *PPTE_ENTRY;

typedef union _PDE_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 Owner : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 LargePage : 1;
        ULONG64 Global : 1;
        ULONG64 CopyOnWrite : 1;
        ULONG64 Prototype : 1;
        ULONG64 Reserved : 1;
        ULONG64 PageFrameNumber : 36;
        ULONG64 ReservedHigh : 15;
        ULONG64 NoExecute : 1;
    };
} PDE_ENTRY, *PPDE_ENTRY;

typedef struct _PTE_HOOK_STATE {
    PVOID           targetVA;
    PPTE_ENTRY      pteAddress;
    ULONG64         originalPfn;
    ULONG64         newPfn;
    PVOID           newPageVA;
    PHYSICAL_ADDRESS newPagePA;
    BOOLEAN         active;
    ULONG           callCount;
    KSPIN_LOCK      lock;
} PTE_HOOK_STATE, *PPTE_HOOK_STATE;

extern PTE_HOOK_STATE g_PteHook;

typedef PPTE_ENTRY(*fnMiGetPteAddress)(PVOID);

BOOLEAN FindMiGetPteAddress();
BOOLEAN SplitLargePage(PPDE_ENTRY pde, PVOID virtualAddress);
BOOLEAN InstallPteHook(PVOID targetAddress, PVOID handlerAddress);
VOID RestorePteHook();
