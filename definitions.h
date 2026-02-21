#pragma once
#include <ntifs.h>
#include <ntddk.h>
// #include <windef.h> // Commented out to prevent conflicts
#include <ntimage.h>
#include <intrin.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

#define DEBUG_BUILD 0
#define CR3_CACHE_SIZE 8
#define MAX_TRANSFER_SIZE (16 * 1024 * 1024)

#if DEBUG_BUILD
#define DBG_PRINT(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[K] " fmt "\n", __VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)
#endif

#define SystemModuleInformation 11
#define SystemHandleInformation 16

#ifndef MAXULONG64
#define MAXULONG64 ((ULONG64)~((ULONG64)0))
#endif

extern "C" {
    // NTKERNELAPI VOID NTAPI KeQuerySystemTime(
    //     OUT PLARGE_INTEGER CurrentTime
    // );

    NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN OUT PSIZE_T RegionSize,
        IN ULONG NewProtect,
        OUT PULONG OldProtect
    );

    NTKERNELAPI NTSTATUS ZwAllocateVirtualMemory(
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN ULONG_PTR ZeroBits,
        IN OUT PSIZE_T RegionSize,
        IN ULONG AllocationType,
        IN ULONG Protect
    );

    NTKERNELAPI NTSTATUS ZwFreeVirtualMemory(
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN OUT PSIZE_T RegionSize,
        IN ULONG FreeType
    );

    NTKERNELAPI PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID Base);
    NTKERNELAPI PVOID RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);

    NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
        ULONG InfoClass,
        PVOID Buffer,
        ULONG Length,
        PULONG ReturnLength
    );
}

typedef struct _PEB_LDR_DATA_KM {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_KM, *PPEB_LDR_DATA_KM;

typedef struct _PEB_KM {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA_KM Ldr;
} PEB_KM, *PPEB_KM;

typedef struct _LDR_DATA_TABLE_ENTRY_KM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_KM, *PLDR_DATA_TABLE_ENTRY_KM;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _PiDDBCacheEntry {
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
    char _pad[16];
} PIDCacheobj, *PPIDCacheobj;

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID ModuleStart;
    PVOID ModuleEnd;
    ULONG64 UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

typedef struct _HASH_BUCKET_ENTRY {
    struct _HASH_BUCKET_ENTRY* Next;
    PVOID DriverName; // Placeholder, used as (PWCH)((ULONG_PTR)Entry + 0x48)
    // Other fields omitted, accessed via offsets
} HASH_BUCKET_ENTRY, *PHASH_BUCKET_ENTRY;

typedef struct _PIDDB_CACHE_ENTRY {
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
    char _0x0028[16];
} PIDDB_CACHE_ENTRY, *PPIDDB_CACHE_ENTRY;

extern PVOID g_SpoofStub;
extern PVOID g_SpoofGadget;
extern PVOID g_KernelBase;
extern ULONG g_KernelSize;
