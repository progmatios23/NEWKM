#pragma once
#include "definitions.h"

typedef PVOID(*fn_spoof_1)(PVOID fn, PVOID a1);
typedef PVOID(*fn_spoof_2)(PVOID fn, PVOID a1, PVOID a2);
typedef PVOID(*fn_spoof_3)(PVOID fn, PVOID a1, PVOID a2, PVOID a3);
typedef PVOID(*fn_spoof_4)(PVOID fn, PVOID a1, PVOID a2, PVOID a3, PVOID a4);

#define SpoofCall1(fn, a1)             ((fn_spoof_1)g_SpoofStub)((PVOID)(fn), (PVOID)(a1))
#define SpoofCall2(fn, a1, a2)         ((fn_spoof_2)g_SpoofStub)((PVOID)(fn), (PVOID)(a1), (PVOID)(a2))
#define SpoofCall3(fn, a1, a2, a3)     ((fn_spoof_3)g_SpoofStub)((PVOID)(fn), (PVOID)(a1), (PVOID)(a2), (PVOID)(a3))
#define SpoofCall4(fn, a1, a2, a3, a4) ((fn_spoof_4)g_SpoofStub)((PVOID)(fn), (PVOID)(a1), (PVOID)(a2), (PVOID)(a3), (PVOID)(a4))

PVOID FindSpoofGadget();
BOOLEAN InitSpoofStub();
BOOLEAN InitSpoofCall();
