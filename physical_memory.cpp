#include "physical_memory.h"

static CR3_CACHE_ENTRY g_Cr3Cache = { 0, 0, 0, FALSE };

VOID InitCR3Cache()
{
    RtlZeroMemory(&g_Cr3Cache, sizeof(g_Cr3Cache));
}

NTSTATUS ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || !physAddr)
        return STATUS_INVALID_PARAMETER;

    MM_COPY_ADDRESS addr;
    addr.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    SIZE_T bytesRead = 0;

    return MmCopyMemory(buffer, addr, size,
        MM_COPY_MEMORY_PHYSICAL, &bytesRead);
}

BOOLEAN ValidateCR3(ULONG64 cr3)
{
    if (cr3 == 0 || (cr3 & 0xFFF) != 0)
        return FALSE;

    ULONG64 pml4e = 0;
    NTSTATUS s = ReadPhysicalAddress(cr3 & PTE_PHYS_MASK, &pml4e, sizeof(pml4e));
    if (!NT_SUCCESS(s))
        return FALSE;

    return (pml4e & PTE_PRESENT) != 0;
}

ULONG64 GetProcessCR3(HANDLE pid)
{
    if (!pid) return 0;

    if (g_Cr3Cache.pid == pid && g_Cr3Cache.locked && g_Cr3Cache.cr3)
        return g_Cr3Cache.cr3;

    if (g_Cr3Cache.pid != pid) {
        g_Cr3Cache.pid    = pid;
        g_Cr3Cache.hits   = 0;
        g_Cr3Cache.cr3    = 0;
        g_Cr3Cache.locked = FALSE;
    }

    g_Cr3Cache.hits++;

    PEPROCESS process = NULL;
    NTSTATUS st;

    if (g_SpoofStub)
        st = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        st = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(st))
        return 0;

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    ULONG64 cr3 = __readcr3();

    if (g_SpoofStub)
        SpoofCall1(KeUnstackDetachProcess, &apc);
    else
        KeUnstackDetachProcess(&apc);

    if (g_SpoofStub)
        SpoofCall1(ObfDereferenceObject, process);
    else
        ObfDereferenceObject(process);

    if (cr3 && ValidateCR3(cr3)) {
        g_Cr3Cache.cr3 = cr3;
        if (g_Cr3Cache.hits >= CR3_LOCK_THRESHOLD)
            g_Cr3Cache.locked = TRUE;
    }

    return cr3;
}

ULONG64 TranslateVirtualAddress(ULONG64 cr3, ULONG64 virtualAddress)
{
    if (!cr3 || !virtualAddress)
        return 0;

    ULONG64 pml4_idx = (virtualAddress >> 39) & 0x1FF;
    ULONG64 pdpt_idx = (virtualAddress >> 30) & 0x1FF;
    ULONG64 pd_idx   = (virtualAddress >> 21) & 0x1FF;
    ULONG64 pt_idx   = (virtualAddress >> 12) & 0x1FF;
    ULONG64 offset   = virtualAddress & PAGE_OFFSET_MASK;

    ULONG64 pte = 0;

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (cr3 & PTE_PHYS_MASK) + pml4_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pdpt_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)
        return (pte & 0xFFFFC0000000ULL) + (virtualAddress & 0x3FFFFFFFULL);

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pd_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)
        return (pte & 0xFFFFFE00000ULL) + (virtualAddress & 0x1FFFFFULL);

    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pt_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    return (pte & PTE_PHYS_MASK) + offset;
}

NTSTATUS PhysicalReadProcessMemory(
    HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || size > MAX_TRANSFER_SIZE)
        return STATUS_INVALID_PARAMETER;

    ULONG64 cr3 = GetProcessCR3(pid);
    if (!cr3)
        return STATUS_UNSUCCESSFUL;

    PUCHAR kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'rPhM');
    if (!kernelBuf)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(kernelBuf, size);

    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T totalRead = 0;

    while (totalRead < size)
    {
        ULONG64 currentVA = address + totalRead;
        SIZE_T pageRemaining = PAGE_SIZE - (currentVA & PAGE_OFFSET_MASK);
        SIZE_T chunkSize = pageRemaining;
        if (chunkSize > size - totalRead)
            chunkSize = size - totalRead;

        ULONG64 physAddr = TranslateVirtualAddress(cr3, currentVA);
        if (!physAddr) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        status = ReadPhysicalAddress(physAddr, kernelBuf + totalRead, chunkSize);
        if (!NT_SUCCESS(status))
            break;

        totalRead += chunkSize;
    }

    if (NT_SUCCESS(status)) {
        __try {
            ProbeForWrite(buffer, size, 1);
            RtlCopyMemory(buffer, kernelBuf, totalRead);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_ACCESS_VIOLATION;
        }
    }

    ExFreePoolWithTag(kernelBuf, 'rPhM');
    return status;
}

NTSTATUS PhysicalWriteProcessMemory(
    HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || size > MAX_TRANSFER_SIZE)
        return STATUS_INVALID_PARAMETER;

    PUCHAR kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'wPhM');
    if (!kernelBuf)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        ProbeForRead(buffer, size, 1);
        RtlCopyMemory(kernelBuf, buffer, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(kernelBuf, 'wPhM');
        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process = NULL;
    NTSTATUS st;

    if (g_SpoofStub)
        st = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        st = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(kernelBuf, 'wPhM');
        return st;
    }

    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apc;

    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    __try {
        RtlCopyMemory((PVOID)address, kernelBuf, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    if (g_SpoofStub) {
        SpoofCall1(KeUnstackDetachProcess, &apc);
        SpoofCall1(ObfDereferenceObject, process);
    } else {
        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
    }

    ExFreePoolWithTag(kernelBuf, 'wPhM');
    return status;
}
