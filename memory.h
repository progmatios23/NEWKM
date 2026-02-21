#pragma once
#include "definitions.h"

PVOID GetSystemModuleBase(const char* moduleName);
PVOID GetSystemModuleExport(const char* moduleName, const char* exportName);

NTSTATUS myReadProcessMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size);
NTSTATUS myWriteProcessMemory(HANDLE pid, ULONG64 address, PVOID buffer, SIZE_T size);

ULONG64 GetProcessModuleBase(HANDLE pid, const wchar_t* moduleName);

NTSTATUS AllocateVirtualMemory(HANDLE pid, ULONG64* outAddress, SIZE_T size, ULONG protect);
NTSTATUS FreeVirtualMemory(HANDLE pid, ULONG64 address, SIZE_T size);
NTSTATUS ProtectVirtualMemory(HANDLE pid, ULONG64 address, SIZE_T size, ULONG newProtect);
