// ServiceProtection.c - Protect services from being stopped/deleted
// Windows 10 x64 ONLY
#include <ntifs.h>
#include <ntstrsafe.h>

// Service protection structures
typedef struct _PROTECTED_SERVICE {
    WCHAR ServiceName[256];
    BOOLEAN IsProtected;
} PROTECTED_SERVICE, * PPROTECTED_SERVICE;

// List of protected services
PROTECTED_SERVICE g_ProtectedServices[] = {
    { L"SimplePYASProtection", TRUE },
    { L"HydraDragonAntivirus", TRUE },
    { L"owlyshield_ransom", TRUE },
    { L"sanctum_ppl_runner", TRUE }
};

LARGE_INTEGER g_RegistryCallbackCookie = { 0 };

// Forward declarations
NTSTATUS ServiceProtectionRegCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

BOOLEAN IsProtectedService(PUNICODE_STRING ServiceName);
BOOLEAN IsServiceRegistryPath(PUNICODE_STRING KeyPath);

NTSTATUS InitializeServiceProtection()
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    RtlInitUnicodeString(&altitude, L"321000");

    // Initialize cookie
    g_RegistryCallbackCookie.QuadPart = 0;

    // Register registry callback to intercept service modifications
    status = CmRegisterCallbackEx(
        ServiceProtectionRegCallback,
        &altitude,
        NULL,
        NULL,
        &g_RegistryCallbackCookie,
        NULL
    );

    if (NT_SUCCESS(status))
    {
        DbgPrint("[Service-Protection] Registry callback registered successfully\r\n");
    }
    else
    {
        DbgPrint("[Service-Protection] Failed to register registry callback: 0x%X\r\n", status);
    }

    return status;
}

VOID CleanupServiceProtection()
{
    if (g_RegistryCallbackCookie.QuadPart != 0)
    {
        CmUnRegisterCallback(g_RegistryCallbackCookie);
        g_RegistryCallbackCookie.QuadPart = 0;
        DbgPrint("[Service-Protection] Registry callback unregistered\r\n");
    }
}

NTSTATUS ServiceProtectionRegCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    NTSTATUS status = STATUS_SUCCESS;

    switch (notifyClass)
    {
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION deleteInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyPath = NULL;

        // Get the full registry path
        status = CmCallbackGetKeyObjectIDEx(
            &g_RegistryCallbackCookie,
            deleteInfo->Object,
            NULL,
            &keyPath,
            0
        );

        if (NT_SUCCESS(status) && keyPath)
        {
            // Check if this is a service key being deleted
            if (IsServiceRegistryPath(keyPath) && IsProtectedService(keyPath))
            {
                DbgPrint("[Service-Protection] BLOCKED: Attempt to delete protected service key: %wZ\r\n", keyPath);
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                return STATUS_ACCESS_DENIED;
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyPath = NULL;

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegistryCallbackCookie,
            setValueInfo->Object,
            NULL,
            &keyPath,
            0
        );

        if (NT_SUCCESS(status) && keyPath)
        {
            // Check if modifying protected service configuration
            if (IsServiceRegistryPath(keyPath) && IsProtectedService(keyPath))
            {
                // Check if trying to modify critical values
                if (setValueInfo->ValueName)
                {
                    UNICODE_STRING start, type, imagePath, deleteFlag;
                    RtlInitUnicodeString(&start, L"Start");
                    RtlInitUnicodeString(&type, L"Type");
                    RtlInitUnicodeString(&imagePath, L"ImagePath");
                    RtlInitUnicodeString(&deleteFlag, L"DeleteFlag");

                    // Block modification of Start, Type, ImagePath, DeleteFlag
                    if (RtlEqualUnicodeString(setValueInfo->ValueName, &start, TRUE) ||
                        RtlEqualUnicodeString(setValueInfo->ValueName, &type, TRUE) ||
                        RtlEqualUnicodeString(setValueInfo->ValueName, &imagePath, TRUE) ||
                        RtlEqualUnicodeString(setValueInfo->ValueName, &deleteFlag, TRUE))
                    {
                        DbgPrint("[Service-Protection] BLOCKED: Attempt to modify protected service value: %wZ\\%wZ\r\n",
                            keyPath, setValueInfo->ValueName);
                        CmCallbackReleaseKeyObjectIDEx(keyPath);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION deleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyPath = NULL;

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegistryCallbackCookie,
            deleteValueInfo->Object,
            NULL,
            &keyPath,
            0
        );

        if (NT_SUCCESS(status) && keyPath)
        {
            if (IsServiceRegistryPath(keyPath) && IsProtectedService(keyPath))
            {
                DbgPrint("[Service-Protection] BLOCKED: Attempt to delete value in protected service: %wZ\r\n", keyPath);
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                return STATUS_ACCESS_DENIED;
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION renameInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
        PUNICODE_STRING keyPath = NULL;

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegistryCallbackCookie,
            renameInfo->Object,
            NULL,
            &keyPath,
            0
        );

        if (NT_SUCCESS(status) && keyPath)
        {
            if (IsServiceRegistryPath(keyPath) && IsProtectedService(keyPath))
            {
                DbgPrint("[Service-Protection] BLOCKED: Attempt to rename protected service key: %wZ\r\n", keyPath);
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                return STATUS_ACCESS_DENIED;
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }
    }

    return STATUS_SUCCESS;
}

BOOLEAN IsServiceRegistryPath(PUNICODE_STRING KeyPath)
{
    if (!KeyPath || !KeyPath->Buffer)
        return FALSE;

    UNICODE_STRING servicesPath;
    RtlInitUnicodeString(&servicesPath, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\");

    // Check if path starts with services registry path (case-insensitive)
    if (KeyPath->Length >= servicesPath.Length)
    {
        UNICODE_STRING prefix;
        prefix.Buffer = KeyPath->Buffer;
        prefix.Length = servicesPath.Length;
        prefix.MaximumLength = servicesPath.Length;

        return RtlEqualUnicodeString(&prefix, &servicesPath, TRUE);
    }

    return FALSE;
}

BOOLEAN IsProtectedService(PUNICODE_STRING KeyPath)
{
    if (!KeyPath || !KeyPath->Buffer)
        return FALSE;

    // Extract service name from path
    // Path format: \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\ServiceName
    PWCHAR serviceName = NULL;
    PWCHAR lastBackslash = NULL;

    // Find last backslash
    for (USHORT i = 0; i < KeyPath->Length / sizeof(WCHAR); i++)
    {
        if (KeyPath->Buffer[i] == L'\\')
            lastBackslash = &KeyPath->Buffer[i];
    }

    if (lastBackslash)
        serviceName = lastBackslash + 1;

    if (!serviceName)
        return FALSE;

    // Check against protected services list
    for (ULONG i = 0; i < ARRAYSIZE(g_ProtectedServices); i++)
    {
        if (g_ProtectedServices[i].IsProtected)
        {
            SIZE_T serviceNameLen = wcslen(g_ProtectedServices[i].ServiceName);
            SIZE_T remainingLen = (KeyPath->Length / sizeof(WCHAR)) - (SIZE_T)(serviceName - KeyPath->Buffer);

            if (remainingLen >= serviceNameLen)
            {
                if (_wcsnicmp(serviceName, g_ProtectedServices[i].ServiceName, serviceNameLen) == 0)
                {
                    // Ensure it's exact match (followed by end of string or backslash)
                    WCHAR nextChar = (remainingLen > serviceNameLen) ? serviceName[serviceNameLen] : L'\0';
                    if (nextChar == L'\0' || nextChar == L'\\')
                    {
                        DbgPrint("[Service-Protection] Matched protected service: %S\r\n",
                            g_ProtectedServices[i].ServiceName);
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}