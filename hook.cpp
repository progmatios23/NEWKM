#include "hook.h"
#include "pte_hook.h"
#include "physical_memory.h"
#include "memory.h"

static PVOID g_HookTarget = NULL;
static PVOID g_OriginalFunction = NULL;
static BOOLEAN g_UsePteHook = FALSE;

// ===== Trampoline for original function passthrough =====
fnOriginalHandler g_OriginalTrampoline = NULL;
static BYTE g_OriginalPrologue[12] = {0};
static PVOID g_TrampolineBuffer = NULL;

static BOOLEAN BuildTrampoline(PVOID targetFunction)
{
    // Save the original 12 bytes BEFORE we overwrite them
    __try {
        RtlCopyMemory(g_OriginalPrologue, targetFunction, 12);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("Failed to read original prologue");
        return FALSE;
    }

    // Allocate executable memory for the trampoline
    // Trampoline layout: [12 bytes original prologue] + [12 bytes JMP back to original+12]
    // Total = 24 bytes
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    g_TrampolineBuffer = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!g_TrampolineBuffer) {
        DBG_PRINT("Failed to allocate trampoline buffer");
        return FALSE;
    }

    RtlZeroMemory(g_TrampolineBuffer, PAGE_SIZE);

    PUCHAR tramp = (PUCHAR)g_TrampolineBuffer;

    // Copy original prologue (first 12 bytes of NtQueryCompositionSurfaceStatistics)
    RtlCopyMemory(tramp, g_OriginalPrologue, 12);

    // Build absolute JMP to original+12 (resume execution after our 12-byte patch)
    // mov rax, <original+12>
    // jmp rax
    PVOID resumeAddr = (PVOID)((PUCHAR)targetFunction + 12);
    tramp[12] = 0x48;          // REX.W prefix
    tramp[13] = 0xB8;          // mov rax, imm64
    *(PVOID*)(tramp + 14) = resumeAddr;
    tramp[22] = 0xFF;          // jmp rax
    tramp[23] = 0xE0;

    g_OriginalTrampoline = (fnOriginalHandler)g_TrampolineBuffer;

    DBG_PRINT("Trampoline built at %p, resume at %p", g_TrampolineBuffer, resumeAddr);
    return TRUE;
}

// ===== Validation =====
FORCEINLINE BOOLEAN ValidateRequest(PREQUEST_DATA req)
{
    __try {
        if (!MmIsAddressValid(req))
            return FALSE;

        ProbeForRead(req, sizeof(REQUEST_DATA), sizeof(ULONG));

        if (req->magic != REQUEST_MAGIC)
            return FALSE;

        if (req->version != REQUEST_VERSION)
            return FALSE;

        if (req->size > MAX_TRANSFER_SIZE)
            return FALSE;

        if (req->command >= 102)
            return FALSE;

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOLEAN InstallInlineHook(PVOID target, PVOID handler)
{
    PMDL mdl = IoAllocateMdl(target, 12, FALSE, FALSE, NULL);
    if (!mdl)
        return FALSE;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return FALSE;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority
    );

    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        MmUnmapLockedPages(mapped, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    BYTE patch[12];
    patch[0] = 0x48;
    patch[1] = 0xB8;
    *(PVOID*)(patch + 2) = handler;
    patch[10] = 0xFF;
    patch[11] = 0xE0;

    memcpy(mapped, patch, 12);

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    DBG_PRINT("Inline hook installed at: %p", target);
    return TRUE;
}

NTSTATUS Hook::Install(PVOID handlerFunction)
{
    PVOID dxgkrnl = GetSystemModuleBase("dxgkrnl.sys");
    if (!dxgkrnl) {
        DBG_PRINT("Failed to find dxgkrnl.sys");
        return STATUS_UNSUCCESSFUL;
    }

    PVOID target = GetSystemModuleExport("dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics");
    if (!target) {
        DBG_PRINT("Failed to find NtQueryCompositionSurfaceStatistics");
        return STATUS_UNSUCCESSFUL;
    }

    g_HookTarget = target;
    g_OriginalFunction = target;

    DBG_PRINT("Hook target: %p", target);

    // CRITICAL: Build trampoline BEFORE installing any hook
    // This saves the original prologue bytes so we can forward legitimate calls
    if (!BuildTrampoline(target)) {
        DBG_PRINT("Failed to build trampoline - aborting hook install");
        return STATUS_UNSUCCESSFUL;
    }

    if (InstallPteHook(target, handlerFunction)) {
        g_UsePteHook = TRUE;
        DBG_PRINT("PTE hook installed successfully");
        return STATUS_SUCCESS;
    }

    DBG_PRINT("PTE hook failed, falling back to inline hook");
    if (InstallInlineHook(target, handlerFunction)) {
        g_UsePteHook = FALSE;
        DBG_PRINT("Inline hook installed successfully");
        return STATUS_SUCCESS;
    }

    DBG_PRINT("All hook methods failed");
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS Hook::Handler(PREQUEST_DATA request)
{
    // Forward ALL non-magic calls to the REAL original function via trampoline
    // This is critical: DWM, Rust, EAC, and all DirectX apps call this function legitimately
    __try {
        if (request->magic != REQUEST_MAGIC) {
            if (g_OriginalTrampoline)
                return g_OriginalTrampoline((PVOID)request);
            return STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_OriginalTrampoline)
            return g_OriginalTrampoline((PVOID)request);
        return STATUS_SUCCESS;
    }

    if (!ValidateRequest(request))
        return STATUS_INVALID_PARAMETER;

    if (g_UsePteHook)
        InterlockedIncrement((volatile LONG*)&g_PteHook.callCount);

    NTSTATUS status = STATUS_SUCCESS;

    switch (request->command) {
        case CMD_PING:
            request->result = g_UsePteHook ? RESPONSE_SUCCESS : RESPONSE_FALLBACK;
            break;

        case CMD_READ:
            status = PhysicalReadProcessMemory(
                (HANDLE)request->pid, request->address,
                (PVOID)request->buffer, (SIZE_T)request->size
            );
            break;

        case CMD_WRITE:
            status = PhysicalWriteProcessMemory(
                (HANDLE)request->pid, request->address,
                (PVOID)request->buffer, (SIZE_T)request->size
            );
            break;

        case CMD_READ64:
            status = myReadProcessMemory(
                (HANDLE)request->pid, request->address,
                (PVOID)request->buffer, (SIZE_T)request->size
            );
            break;

        case CMD_WRITE64:
            status = myWriteProcessMemory(
                (HANDLE)request->pid, request->address,
                (PVOID)request->buffer, (SIZE_T)request->size
            );
            break;

        case CMD_MODULE_BASE:
            request->result = GetProcessModuleBase(
                (HANDLE)request->pid, request->module_name
            );
            break;

        case CMD_ALLOC:
            status = AllocateVirtualMemory(
                (HANDLE)request->pid, &request->result,
                (SIZE_T)request->size, request->protect
            );
            break;

        case CMD_FREE:
            status = FreeVirtualMemory(
                (HANDLE)request->pid, request->address,
                (SIZE_T)request->size
            );
            break;

        case CMD_PROTECT:
            status = ProtectVirtualMemory(
                (HANDLE)request->pid, request->address,
                (SIZE_T)request->size, request->protect
            );
            break;

        case CMD_VERIFY_PTE:
            if (g_UsePteHook)
                request->result = (ULONG64)&g_PteHook;
            break;

        case CMD_VERIFY_SPOOF:
            request->result = (ULONG64)g_SpoofGadget;
            break;

        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    return status;
}
