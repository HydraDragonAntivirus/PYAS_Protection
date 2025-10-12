// Service.c - Protect services from being stopped/deleted
// Windows 10 x64 ONLY
#include <ntifs.h>
#include <ntstrsafe.h>

typedef struct _PROTECTED_SERVICE {
    WCHAR ServiceName[256];
    BOOLEAN IsProtected;
} PROTECTED_SERVICE, * PPROTECTED_SERVICE;

static PROTECTED_SERVICE g_ProtectedServices[] = {
    { L"SimplePYASProtection", TRUE },
    { L"HydraDragonAntivirus", TRUE },
    { L"owlyshield_ransom", TRUE },
    { L"sanctum_ppl_runner", TRUE }
};

static LARGE_INTEGER g_RegistryCallbackCookie = { 0 };

/* Forward declarations */
NTSTATUS ServiceProtectionRegCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

BOOLEAN IsProtectedServicePath(_In_ PUNICODE_STRING KeyPath);

/* InitializeServiceProtection */
NTSTATUS InitializeServiceProtection()
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    RtlInitUnicodeString(&altitude, L"321000");

    g_RegistryCallbackCookie.QuadPart = 0;

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
        DbgPrint("[Service-Protection] Registry callback registered successfully (cookie: 0x%llx)\n",
            g_RegistryCallbackCookie.QuadPart);
    }
    else
    {
        DbgPrint("[Service-Protection] Failed to register registry callback: 0x%X\n", status);
    }

    return status;
}

/* CleanupServiceProtection */
VOID CleanupServiceProtection()
{
    if (g_RegistryCallbackCookie.QuadPart != 0)
    {
        CmUnRegisterCallback(g_RegistryCallbackCookie);
        g_RegistryCallbackCookie.QuadPart = 0;
        DbgPrint("[Service-Protection] Registry callback unregistered\n");
    }
}

/* ServiceProtectionRegCallback */
NTSTATUS ServiceProtectionRegCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    NTSTATUS status = STATUS_SUCCESS;
    PUNICODE_STRING keyPath = NULL;

    switch (notifyClass)
    {
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION deleteInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
        status = CmCallbackGetKeyObjectIDEx(&g_RegistryCallbackCookie,
            deleteInfo->Object,
            NULL,
            &keyPath,
            0);
        if (NT_SUCCESS(status) && keyPath)
        {
            DbgPrint("[Service-Protection] RegNtPreDeleteKey Path: %wZ\n", keyPath);
            if (IsProtectedServicePath(keyPath))
            {
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                DbgPrint("[Service-Protection] BLOCKED: Attempt to delete protected service key\n");
                return STATUS_ACCESS_DENIED;
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        status = CmCallbackGetKeyObjectIDEx(&g_RegistryCallbackCookie,
            setValueInfo->Object,
            NULL,
            &keyPath,
            0);
        if (NT_SUCCESS(status) && keyPath)
        {
            UNICODE_STRING emptyName = RTL_CONSTANT_STRING(L"");
            PUNICODE_STRING printName = (setValueInfo->ValueName) ? setValueInfo->ValueName : &emptyName;

            DbgPrint("[Service-Protection] RegNtPreSetValueKey Path: %wZ Value: %wZ\n",
                keyPath, printName);

            if (IsProtectedServicePath(keyPath) && setValueInfo->ValueName)
            {
                UNICODE_STRING start, type, imagePath, deleteFlag;
                RtlInitUnicodeString(&start, L"Start");
                RtlInitUnicodeString(&type, L"Type");
                RtlInitUnicodeString(&imagePath, L"ImagePath");
                RtlInitUnicodeString(&deleteFlag, L"DeleteFlag");

                if (RtlEqualUnicodeString(setValueInfo->ValueName, &start, TRUE) ||
                    RtlEqualUnicodeString(setValueInfo->ValueName, &type, TRUE) ||
                    RtlEqualUnicodeString(setValueInfo->ValueName, &imagePath, TRUE) ||
                    RtlEqualUnicodeString(setValueInfo->ValueName, &deleteFlag, TRUE))
                {
                    CmCallbackReleaseKeyObjectIDEx(keyPath);
                    DbgPrint("[Service-Protection] BLOCKED: Attempt to modify protected service value: %wZ\\%wZ\n",
                        keyPath, setValueInfo->ValueName);
                    return STATUS_ACCESS_DENIED;
                }
            }

            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION deleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        status = CmCallbackGetKeyObjectIDEx(&g_RegistryCallbackCookie,
            deleteValueInfo->Object,
            NULL,
            &keyPath,
            0);
        if (NT_SUCCESS(status) && keyPath)
        {
            DbgPrint("[Service-Protection] RegNtPreDeleteValueKey Path: %wZ\n", keyPath);
            if (IsProtectedServicePath(keyPath))
            {
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                DbgPrint("[Service-Protection] BLOCKED: Attempt to delete value in protected service\n");
                return STATUS_ACCESS_DENIED;
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION renameInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
        status = CmCallbackGetKeyObjectIDEx(&g_RegistryCallbackCookie,
            renameInfo->Object,
            NULL,
            &keyPath,
            0);
        if (NT_SUCCESS(status) && keyPath)
        {
            DbgPrint("[Service-Protection] RegNtPreRenameKey Path: %wZ\n", keyPath);
            if (IsProtectedServicePath(keyPath))
            {
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                DbgPrint("[Service-Protection] BLOCKED: Attempt to rename protected service key\n");
                return STATUS_ACCESS_DENIED;
            }
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
        break;
    }

    default:
        break;
    }

    return STATUS_SUCCESS;
}

/* IsProtectedServicePath
 * Detects the service name in a registry path by searching for "\Services\" and comparing
 * the following token to protected names.
 */
BOOLEAN IsProtectedServicePath(_In_ PUNICODE_STRING KeyPath)
{
    UNICODE_STRING token = RTL_CONSTANT_STRING(L"\\Services\\");
    if (!KeyPath || !KeyPath->Buffer || KeyPath->Length == 0)
        return FALSE;

    USHORT totalChars = (USHORT)(KeyPath->Length / sizeof(WCHAR));
    PWCHAR buf = KeyPath->Buffer;
    USHORT tokenChars = (USHORT)(token.Length / sizeof(WCHAR));

    for (USHORT i = 0; i + tokenChars <= totalChars; i++)
    {
        UNICODE_STRING slice;
        slice.Buffer = &buf[i];
        slice.Length = token.Length;
        slice.MaximumLength = token.Length;

        if (RtlEqualUnicodeString(&slice, &token, TRUE))
        {
            USHORT svcStart = (USHORT)(i + tokenChars);
            if (svcStart >= totalChars)
                return FALSE;

            USHORT svcLenChars = 0;
            for (USHORT j = svcStart; j < totalChars; j++)
            {
                if (buf[j] == L'\\')
                    break;
                svcLenChars++;
            }

            if (svcLenChars == 0)
                return FALSE;

            UNICODE_STRING svcName;
            svcName.Buffer = &buf[svcStart];
            svcName.Length = (USHORT)(svcLenChars * sizeof(WCHAR));
            svcName.MaximumLength = svcName.Length;

            for (ULONG k = 0; k < ARRAYSIZE(g_ProtectedServices); k++)
            {
                if (!g_ProtectedServices[k].IsProtected)
                    continue;

                UNICODE_STRING prot;
                RtlInitUnicodeString(&prot, g_ProtectedServices[k].ServiceName);
                if (RtlEqualUnicodeString(&svcName, &prot, TRUE))
                {
                    DbgPrint("[Service-Protection] Matched protected service: %wZ (path: %wZ)\n", &prot, KeyPath);
                    return TRUE;
                }
            }

            return FALSE;
        }
    }

    return FALSE;
}
