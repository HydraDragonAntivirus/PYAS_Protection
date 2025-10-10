#pragma once

#include <ntifs.h>

#define REG_TAG 'gkER'
#define REG_PROTECT_SUBPATH L"\\SOFTWARE\\OWLYSHIELD"

// Driver Entry ve Unload
NTSTATUS RegeditDriverEntry();
NTSTATUS RegeditUnloadDriver();

// Registry Callback
NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

BOOLEAN GetNameForRegistryObject(
    _Out_ PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(
    _In_ PUNICODE_STRING Source,
    _In_ PCWSTR Pattern
);
