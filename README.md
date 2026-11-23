# NEWKM: Windows x64 Kernel Driver

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-blue.svg)]()
[![Architecture](https://img.shields.io/badge/arch-x86__64-orange.svg)]()
[![Language](https://img.shields.io/badge/language-C%20%2F%20C%2B%2B-red.svg)]()
[![Mapping](https://img.shields.io/badge/manual%20mapping-kdmapper-green.svg)]()

High-performance Windows x64 kernel driver implementing manual mapping compatibility (`kdmapper`), Page Table Entry (PTE) manipulation, physical memory address translation, and synthetic call stack spoofing.

---

## 🛠️ Key Architectural Components

### 1. Manual Mapping Support (kdmapper)
* Designed for runtime injection via vulnerable signed drivers (e.g., `iqvw64e.sys` / `kdmapper`).
* Bypasses Driver Signature Enforcement (DSE) without registering persistent services or adding system driver entries (`DriverObject` cleanup).
* Zero system thread traces with clean entrypoint dispatching.

### 2. Page Table Entry (PTE) & Memory Management
* **CR3 Directory Base Traversal**: Walks PML4, PDPT, PD, and PT levels to translate virtual memory addresses to physical addresses directly.
* **PTE Hooking (`pte_hook.cpp`)**: Modifies page table attributes (e.g., clearing `Supervisor` bit or setting `Write` permissions) to access protected physical frames without triggering PatchGuard / KPP heuristics.
* **Direct Physical Memory Access**: Reads and writes physical RAM buffers bypassing standard `MmCopyVirtualMemory` traps.

### 3. Synthetic Call Stack Spoofing (`spoof_call.cpp`)
* Spoofs kernel return addresses during inter-module execution to evade heuristic stack walking mechanisms.
* Emulates legitimate kernel module frames (e.g., `ntoskrnl.exe` or standard drivers) to prevent detection by anti-cheat kernel threads.

---

## 📁 Repository Structure

```
NEWKM/
├── Driver.sln               # Visual Studio Solution
├── Driver.vcxproj           # WDK Kernel Project
├── pte_hook.cpp / .h        # Page Table Entry manipulation & hook routines
├── spoof_call.cpp / .h      # Call stack spoofing implementation
├── shared.h                 # Inter-ring communications, IOCTL definitions & structs
└── physical_memory.md       # Architectural notes on x64 virtual-to-physical translation
```

---

## 🔨 Build Instructions

### Prerequisites
* Visual Studio 2022 (Desktop Development with C++)
* Windows 10/11 WDK (Windows Driver Kit) matching target OS build
* Configuration: `Release | x64`

### Compiling
1. Open `Driver.sln` in Visual Studio 2022.
2. Select target configuration: `Release` and architecture: `x64`.
3. Build Solution (`Ctrl+Shift+B`).
4. Output binary: `x64/Release/Driver.sys`.

---

## ⚠️ Disclaimer
This codebase is maintained strictly for educational purposes, OS internals research, and hardware driver exploration.
