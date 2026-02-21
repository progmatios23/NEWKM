#pragma once
#include "definitions.h"
#include "shared.h"

// Original function signature for NtQueryCompositionSurfaceStatistics
typedef NTSTATUS(*fnOriginalHandler)(PVOID);

// Trampoline to the real original function
extern fnOriginalHandler g_OriginalTrampoline;

namespace Hook {
    NTSTATUS Install(PVOID handlerFunction);
    NTSTATUS Handler(PREQUEST_DATA request);
}
