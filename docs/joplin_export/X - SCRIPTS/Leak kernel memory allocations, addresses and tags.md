---
title: Leak kernel memory allocations, addresses and tags
updated: 2025-04-30 12:12:45Z
created: 2025-04-30 12:09:44Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

File: query.c
```
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// NTSTATUS definition
typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

// SYSTEM_INFORMATION_CLASS enum
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASS;

// SYSTEM_BIGPOOL_ENTRY struct
typedef struct _SYSTEM_BIGPOOL_ENTRY {
    PVOID VirtualAddress;
    SIZE_T SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    BOOLEAN NonPaged;
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

// SYSTEM_BIGPOOL_INFORMATION struct
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY Allocations[1]; // variable-sized array
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

// Function prototype for NtQuerySystemInformation
typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

int main() {
    printf("[*] Loading ntdll.dll...\n");
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        printf("[!] Failed to load ntdll.dll\n");
        return 1;
    }

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("[!] Failed to get NtQuerySystemInformation\n");
        return 1;
    }

    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS status;
    ULONG returnLength = 0;

    do {
        free(buffer);
        buffer = malloc(bufferSize);
        if (!buffer) {
            printf("[!] Memory allocation failed\n");
            return 1;
        }

        status = NtQuerySystemInformation(
            SystemBigPoolInformation,
            buffer,
            bufferSize,
            &returnLength
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != 0) {
        printf("[!] NtQuerySystemInformation failed: 0x%X\n", status);
        free(buffer);
        return 1;
    }

    PSYSTEM_BIGPOOL_INFORMATION bigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)buffer;
    printf("[*] Found %lu big pool entries\n", bigPoolInfo->Count);

    for (ULONG i = 0; i < bigPoolInfo->Count; i++) {
        char tag[5] = {0};
        memcpy(tag, bigPoolInfo->Allocations[i].Tag, 4);
        printf("Tag: %s | Size: 0x%zX | Address: %p | NonPaged: %s\n",
               tag,
               bigPoolInfo->Allocations[i].SizeInBytes,
               bigPoolInfo->Allocations[i].VirtualAddress,
               bigPoolInfo->Allocations[i].NonPaged ? "Yes" : "No");
    }

    free(buffer);
    return 0;
}
```


Cross-Compile for Windows 64-bit 
`x86_64-w64-mingw32-gcc query.c -o query.exe`
