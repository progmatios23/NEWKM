#include "driver.h"
#include "definitions.h"
#include "shared.h"
#include "hook.h"
#include "cleaner.h"
#include "spoof_call.h"
#include "physical_memory.h"

PVOID g_SpoofStub = NULL;
PVOID g_SpoofGadget = NULL;
PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

PVOID GetKernelBase(PULONG outSize)
{
    PVOID baseAddr = NULL;
    ULONG size = 0;

    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformation, NULL, 0, &size);

    if (size == 0)
        return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, size, 'mKnK');

    if (!modules)
        return NULL;

    status = ZwQuerySystemInformation(
        SystemModuleInformation, modules, size, &size);

    if (NT_SUCCESS(status) && modules->NumberOfModules > 0) {
        baseAddr = modules->Modules[0].ImageBase;
        if (outSize)
            *outSize = modules->Modules[0].ImageSize;
    }

    ExFreePoolWithTag(modules, 'mKnK');
    return baseAddr;
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    DBG_PRINT("DriverEntry called");

    // ===== STEP 1: Get kernel base (safe) =====
    g_KernelBase = GetKernelBase(&g_KernelSize);
    if (!g_KernelBase) {
        DBG_PRINT("Failed to get kernel base");
        return STATUS_UNSUCCESSFUL;
    }

    DBG_PRINT("Kernel base: %p, size: 0x%X", g_KernelBase, g_KernelSize);

    // ===== STEP 2: Init spoof call (optional, non-fatal) =====
    // Disabled by default - the shellcode approach is risky and can BSOD
    // if the gadget pattern doesn't match or pool allocation flags are wrong.
    // Uncomment when you have verified the gadget on your specific Windows version.
    /*
    if (!InitSpoofCall()) {
        DBG_PRINT("Spoof call initialization failed, continuing without");
        g_SpoofStub = NULL;
    } else {
        DBG_PRINT("Spoof call initialized successfully");
    }
    */
    g_SpoofStub = NULL; // Explicitly disabled for safety
    DBG_PRINT("Spoof call DISABLED for safety");

    // ===== STEP 3: Init CR3 cache (safe) =====
    InitCR3Cache();
    DBG_PRINT("CR3 cache initialized");

    // ===== STEP 4: Install hook (critical) =====
    status = Hook::Install(&Hook::Handler);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("Hook installation failed: 0x%X", status);
        return status;
    }

    DBG_PRINT("Hook installed successfully");

    // ===== STEP 5: Clean traces (risky, wrapped in SEH) =====
    // Each cleaner function can crash if patterns don't match your Windows version.
    // We wrap the entire cleanup in SEH to prevent BSOD.
    __try {
        // PiDDB cleanup - risky, pattern-dependent
        if (!CleanPiDDBCacheTable()) {
            DBG_PRINT("Failed to clean PiDDB (non-fatal)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("EXCEPTION in CleanPiDDB - skipped");
    }

    __try {
        // MmUnloadedDrivers cleanup
        if (!CleanMmUnloadedDrivers(L"iqvw64e.sys")) {
            DBG_PRINT("Failed to clean MmUnloadedDrivers (non-fatal)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("EXCEPTION in CleanMmUnloadedDrivers - skipped");
    }

    __try {
        // Hash bucket cleanup
        if (!CleanKernelHashBucket(L"iqvw64e.sys")) {
            DBG_PRINT("Failed to clean HashBucket (non-fatal)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("EXCEPTION in CleanKernelHashBucket - skipped");
    }

    // ===== STEP 6: Hide driver object (risky with KDMapper) =====
    // KDMapper manually maps the driver, DriverObject may have limited
    // validity. Only hide if DriverObject looks valid.
    __try {
        if (DriverObject && MmIsAddressValid(DriverObject)) {
            HideDriverObject(DriverObject);
            DBG_PRINT("Driver object hidden");
        } else {
            DBG_PRINT("DriverObject invalid, skipping HideDriverObject");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("EXCEPTION in HideDriverObject - skipped");
    }

    if (DriverObject)
        DriverObject->DriverUnload = NULL;

    DBG_PRINT("Driver initialization complete");
    return STATUS_SUCCESS;
}
