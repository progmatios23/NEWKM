#include "pte_hook.h"

PTE_HOOK_STATE g_PteHook = {0};
static fnMiGetPteAddress MiGetPteAddress = NULL;

static const BYTE MiGetPtePattern[] = {
    0x48, 0xC1, 0xE9, 0x09,
    0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x48, 0x23, 0xC8,
    0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x48, 0x03, 0xC1,
    0xC3
};

BOOLEAN FindMiGetPteAddress()
{
    if (!g_KernelBase || !g_KernelSize)
        return FALSE;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)g_KernelBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)g_KernelBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            PUCHAR start = (PUCHAR)g_KernelBase + section[i].VirtualAddress;
            ULONG size = section[i].Misc.VirtualSize;

            for (ULONG offset = 0; offset < size - sizeof(MiGetPtePattern); offset++) {
                BOOLEAN match = TRUE;
                for (SIZE_T j = 0; j < sizeof(MiGetPtePattern); j++) {
                    if (MiGetPtePattern[j] != 0xCC && start[offset + j] != MiGetPtePattern[j]) {
                        match = FALSE;
                        break;
                    }
                }

                if (match) {
                    MiGetPteAddress = (fnMiGetPteAddress)(start + offset);
                    DBG_PRINT("Found MiGetPteAddress at: %p", MiGetPteAddress);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

BOOLEAN SplitLargePage(PPDE_ENTRY pde, PVOID virtualAddress)
{
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    PVOID newPageTable = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!newPageTable)
        return FALSE;

    RtlZeroMemory(newPageTable, PAGE_SIZE);

    PPTE_ENTRY ptes = (PPTE_ENTRY)newPageTable;
    ULONG64 basePfn = pde->PageFrameNumber << 9;

    for (int i = 0; i < 512; i++) {
        ptes[i].Present = 1;
        ptes[i].Write = pde->Write;
        ptes[i].Owner = pde->Owner;
        ptes[i].PageFrameNumber = basePfn + i;
        ptes[i].NoExecute = pde->NoExecute;
    }

    PHYSICAL_ADDRESS newPtPhys = MmGetPhysicalAddress(newPageTable);

    PDE_ENTRY newPde = {0};
    newPde.Present = 1;
    newPde.Write = pde->Write;
    newPde.Owner = pde->Owner;
    newPde.LargePage = 0;
    newPde.PageFrameNumber = newPtPhys.QuadPart >> 12;
    newPde.NoExecute = pde->NoExecute;

    InterlockedExchange64((LONG64*)pde, newPde.Value);

    ULONG64 baseVA = (ULONG64)virtualAddress & ~0x1FFFFF;
    for (int i = 0; i < 512; i++) {
        __invlpg((PVOID)(baseVA + (i * PAGE_SIZE)));
    }

    return TRUE;
}

BOOLEAN InstallPteHook(PVOID targetAddress, PVOID handlerAddress)
{
    if (!FindMiGetPteAddress()) {
        DBG_PRINT("Failed to find MiGetPteAddress");
        return FALSE;
    }

    KeInitializeSpinLock(&g_PteHook.lock);

    PPTE_ENTRY pte = MiGetPteAddress(targetAddress);
    if (!pte || !pte->Present) {
        DBG_PRINT("PTE not present for address: %p", targetAddress);
        return FALSE;
    }

    PVOID pdeAddr = MiGetPteAddress(pte);
    PPDE_ENTRY pde = (PPDE_ENTRY)pdeAddr;

    if (pde->Present && pde->LargePage) {
        DBG_PRINT("Splitting large page for address: %p", targetAddress);
        if (!SplitLargePage(pde, targetAddress)) {
            DBG_PRINT("Failed to split large page");
            return FALSE;
        }
        pte = MiGetPteAddress(targetAddress);
    }

    g_PteHook.originalPfn = pte->PageFrameNumber;

    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    PVOID newPage = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!newPage) {
        DBG_PRINT("Failed to allocate new page");
        return FALSE;
    }

    PHYSICAL_ADDRESS originalPA;
    originalPA.QuadPart = g_PteHook.originalPfn << 12;

    PVOID originalMapped = MmMapIoSpaceEx(originalPA, PAGE_SIZE, PAGE_READWRITE);
    if (!originalMapped) {
        MmFreeContiguousMemory(newPage);
        DBG_PRINT("Failed to map original page");
        return FALSE;
    }

    RtlCopyMemory(newPage, originalMapped, PAGE_SIZE);
    MmUnmapIoSpace(originalMapped, PAGE_SIZE);

    ULONG offset = (ULONG)((ULONG64)targetAddress & 0xFFF);
    PUCHAR hookLocation = (PUCHAR)newPage + offset;

    hookLocation[0] = 0x48;
    hookLocation[1] = 0xB8;
    *(PVOID*)(hookLocation + 2) = handlerAddress;
    hookLocation[10] = 0xFF;
    hookLocation[11] = 0xE0;

    g_PteHook.newPagePA = MmGetPhysicalAddress(newPage);
    g_PteHook.newPfn = g_PteHook.newPagePA.QuadPart >> 12;

    PTE_ENTRY newPte = *pte;
    newPte.PageFrameNumber = g_PteHook.newPfn;

    InterlockedExchange64((LONG64*)pte, newPte.Value);
    __invlpg(targetAddress);

    g_PteHook.targetVA = targetAddress;
    g_PteHook.pteAddress = pte;
    g_PteHook.newPageVA = newPage;
    g_PteHook.active = TRUE;
    g_PteHook.callCount = 0;

    DBG_PRINT("PTE hook installed at: %p -> %p", targetAddress, handlerAddress);
    return TRUE;
}

VOID RestorePteHook()
{
    if (!g_PteHook.active)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PteHook.lock, &oldIrql);

    if (g_PteHook.pteAddress) {
        PTE_ENTRY restoredPte = *g_PteHook.pteAddress;
        restoredPte.PageFrameNumber = g_PteHook.originalPfn;

        InterlockedExchange64((LONG64*)g_PteHook.pteAddress, restoredPte.Value);
        __invlpg(g_PteHook.targetVA);
    }

    if (g_PteHook.newPageVA) {
        MmFreeContiguousMemory(g_PteHook.newPageVA);
    }

    RtlZeroMemory(&g_PteHook, sizeof(PTE_HOOK_STATE));

    KeReleaseSpinLock(&g_PteHook.lock, oldIrql);
}
