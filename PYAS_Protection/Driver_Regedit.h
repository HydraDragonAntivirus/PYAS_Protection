#pragma once

#include <ntifs.h>

// Pool tag tanýmý
#define REG_TAG 'gkER'  // 4-byte pool tag (ters sýrada: ERkg)
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

// Yardýmcý fonksiyonlar - DÜZELTME: 2 parametre
BOOLEAN GetNameForRegistryObject(
    _Out_ PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(
    _In_ PUNICODE_STRING Source,
    _In_ PCWSTR Pattern
);
