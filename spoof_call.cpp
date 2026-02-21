#include "spoof_call.h"

static const BYTE SpoofGadgetPattern[] = { 0x48, 0x83, 0xC4, 0x28, 0xC3 };

static const BYTE SpoofShellcode[] = {
    0x41, 0x5B,
    0x48, 0x8B, 0xC1,
    0x48, 0x8B, 0xCA,
    0x49, 0x8B, 0xD0,
    0x4D, 0x8B, 0xC1,
    0x4C, 0x8B, 0x4C, 0x24, 0x20,
    0x48, 0x83, 0xEC, 0x38,
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x89, 0x14, 0x24,
    0x4C, 0x89, 0x5C, 0x24, 0x30,
    0xFF, 0xE0
};

PVOID FindSpoofGadget()
{
    if (!g_KernelBase || !g_KernelSize)
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)g_KernelBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)g_KernelBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PUCHAR start = (PUCHAR)g_KernelBase + section[i].VirtualAddress;
            ULONG size = section[i].Misc.VirtualSize;

            for (ULONG offset = 0; offset < size - sizeof(SpoofGadgetPattern); offset++) {
                if (memcmp(start + offset, SpoofGadgetPattern, sizeof(SpoofGadgetPattern)) == 0) {
                    DBG_PRINT("Found spoof gadget at: %p", start + offset);
                    return (PVOID)(start + offset);
                }
            }
        }
    }

    return NULL;
}

BOOLEAN InitSpoofStub()
{
    if (!g_SpoofGadget)
        return FALSE;

    PVOID stub = ExAllocatePoolWithTag(
        NonPagedPoolExecute,
        sizeof(SpoofShellcode),
        'fpSK'
    );

    if (!stub)
        return FALSE;

    RtlCopyMemory(stub, SpoofShellcode, sizeof(SpoofShellcode));
    *(PVOID*)((PUCHAR)stub + 25) = g_SpoofGadget;

    g_SpoofStub = stub;
    DBG_PRINT("Spoof stub initialized at: %p", g_SpoofStub);
    return TRUE;
}

BOOLEAN InitSpoofCall()
{
    g_SpoofGadget = FindSpoofGadget();
    if (!g_SpoofGadget) {
        DBG_PRINT("Failed to find spoof gadget");
        return FALSE;
    }

    if (!InitSpoofStub()) {
        DBG_PRINT("Failed to initialize spoof stub");
        return FALSE;
    }

    return TRUE;
}
