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

/*
    Gets the full name for a registry object. To prevent static analysis warnings,
    ensure the function definition in your .c file has matching SAL annotations.

    Parameters:
        pRegistryPath: A pointer to a UNICODE_STRING structure.
            - On input, the MaximumLength field must be set to the size of the buffer in bytes.
            - On input, the Buffer field must point to a non-paged pool allocation of at least MaximumLength bytes.
            - On successful return, the Length field is updated with the length of the name string,
              and the Buffer is filled with the name.
        pRegistryObject: A pointer to the registry object (e.g., a key handle).

    Return:
        TRUE on success, FALSE on failure.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(
    _In_ PUNICODE_STRING Source,
    _In_ PCWSTR Pattern
);

