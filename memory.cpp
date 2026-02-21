#include "memory.h"
#include "shared.h"
#include "spoof_call.h"

PVOID GetSystemModuleBase(const char* moduleName)
{
    ULONG size = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);

    if (size == 0)
        return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, size, 'mSyK');

    if (!modules)
        return NULL;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, &size);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'mSyK');
        return NULL;
    }

    PVOID baseAddr = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        char* currentName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
        if (_stricmp(currentName, moduleName) == 0) {
            baseAddr = modules->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, 'mSyK');
    return baseAddr;
}

PVOID GetSystemModuleExport(const char* moduleName, const char* exportName)
{
    PVOID moduleBase = GetSystemModuleBase(moduleName);
    if (!moduleBase)
        return NULL;

    return RtlFindExportedRoutineByName(moduleBase, exportName);
}

NTSTATUS myReadProcessMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status))
        return status;

    SIZE_T bytesRead = 0;
    status = MmCopyVirtualMemory(
        process, (PVOID)address,
        PsGetCurrentProcess(), buffer,
        size, KernelMode, &bytesRead
    );

    if (g_SpoofStub)
        SpoofCall1(ObfDereferenceObject, process);
    else
        ObfDereferenceObject(process);

    return status;
}

NTSTATUS myWriteProcessMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status))
        return status;

    SIZE_T bytesWritten = 0;
    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(), buffer,
        process, (PVOID)address,
        size, KernelMode, &bytesWritten
    );

    if (g_SpoofStub)
        SpoofCall1(ObfDereferenceObject, process);
    else
        ObfDereferenceObject(process);

    return status;
}

ULONG64 GetProcessModuleBase(HANDLE pid, const wchar_t* moduleName)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status))
        return 0;

    wchar_t moduleNameCopy[MAX_MODULE_NAME_LEN];
    wcscpy_s(moduleNameCopy, MAX_MODULE_NAME_LEN, moduleName);

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    ULONG64 moduleBase = 0;

    __try {
        PPEB_KM peb = (PPEB_KM)PsGetProcessPeb(process);
        if (peb && peb->Ldr) {
            for (PLIST_ENTRY listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
                 listEntry != &peb->Ldr->InLoadOrderModuleList;
                 listEntry = listEntry->Flink) {

                PLDR_DATA_TABLE_ENTRY_KM ldrEntry = CONTAINING_RECORD(
                    listEntry, LDR_DATA_TABLE_ENTRY_KM, InLoadOrderLinks);

                if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0) {
                    if (_wcsicmp(ldrEntry->BaseDllName.Buffer, moduleNameCopy) == 0) {
                        moduleBase = (ULONG64)ldrEntry->DllBase;
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        moduleBase = 0;
    }

    if (g_SpoofStub) {
        SpoofCall1(KeUnstackDetachProcess, &apc);
        SpoofCall1(ObfDereferenceObject, process);
    } else {
        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
    }

    return moduleBase;
}

NTSTATUS AllocateVirtualMemory(HANDLE pid, ULONG64* outAddress, SIZE_T size, ULONG protect)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status))
        return status;

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    PVOID baseAddr = NULL;
    SIZE_T regionSize = size;

    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &baseAddr, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, protect
    );

    if (NT_SUCCESS(status) && outAddress)
        *outAddress = (ULONG64)baseAddr;

    if (g_SpoofStub) {
        SpoofCall1(KeUnstackDetachProcess, &apc);
        SpoofCall1(ObfDereferenceObject, process);
    } else {
        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
    }

    return status;
}

NTSTATUS FreeVirtualMemory(HANDLE pid, ULONG64 address, SIZE_T size)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status))
        return status;

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    PVOID baseAddr = (PVOID)address;
    SIZE_T regionSize = size;

    status = ZwFreeVirtualMemory(
        ZwCurrentProcess(), &baseAddr, &regionSize, MEM_RELEASE
    );

    if (g_SpoofStub) {
        SpoofCall1(KeUnstackDetachProcess, &apc);
        SpoofCall1(ObfDereferenceObject, process);
    } else {
        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
    }

    return status;
}

NTSTATUS ProtectVirtualMemory(HANDLE pid, ULONG64 address, SIZE_T size, ULONG newProtect)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (g_SpoofStub)
        status = (NTSTATUS)(ULONG_PTR)SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        status = PsLookupProcessByProcessId(pid, &process);

    if (!NT_SUCCESS(status))
        return status;

    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    PVOID baseAddr = (PVOID)address;
    SIZE_T regionSize = size;
    ULONG oldProtect = 0;

    status = ZwProtectVirtualMemory(
        ZwCurrentProcess(), &baseAddr, &regionSize, newProtect, &oldProtect
    );

    if (g_SpoofStub) {
        SpoofCall1(KeUnstackDetachProcess, &apc);
        SpoofCall1(ObfDereferenceObject, process);
    } else {
        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
    }

    return status;
}
