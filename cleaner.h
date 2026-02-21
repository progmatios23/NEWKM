#pragma once
#include "definitions.h"

PVOID ResolveRelativeAddress(PVOID instruction, ULONG offsetToRip, ULONG instructionSize);
PVOID FindPattern(PVOID baseAddress, ULONG size, const BYTE* pattern, SIZE_T patternSize);
PVOID GetPageSection(PULONG outSize);
BOOLEAN CleanPiDDBCacheTable();
BOOLEAN CleanPiDDBCacheTable();
BOOLEAN CleanKernelHashBucket(const wchar_t* driverName);
BOOLEAN CleanMmUnloadedDrivers(const wchar_t* driverName);
VOID HideDriverObject(PDRIVER_OBJECT DriverObject);
VOID CleanAllTraces(PDRIVER_OBJECT DriverObject);
