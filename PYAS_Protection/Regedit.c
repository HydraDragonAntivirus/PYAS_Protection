// Regedit.c - Registry protection with user-mode alerting
#include "Driver_Regedit.h"
#include <ntstrsafe.h>

#define REG_TAG 'gkER'
#define REG_PROTECT_SUBPATH L"\\SOFTWARE\\OWLYSHIELD"
#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

LARGE_INTEGER Cookie;

// Prototypes
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
BOOLEAN GetNameForRegistryObject(_Out_ PUNICODE_STRING pRegistryPath, _In_ PVOID pRegistryObject);
BOOLEAN UnicodeContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);
NTSTATUS SendRegistryAlertToUserMode(PUNICODE_STRING RegPath, PCWSTR Operation);

NTSTATUS RegeditDriverEntry()
{
    CmRegisterCallback(RegistryCallback, NULL, &Cookie);
    return STATUS_SUCCESS;
}

NTSTATUS RegeditUnloadDriver()
{
    CmUnRegisterCallback(Cookie);
    return STATUS_SUCCESS;
}

NTSTATUS SendRegistryAlertToUserMode(
    PUNICODE_STRING RegPath,
    PCWSTR Operation
)
{
    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    WCHAR messageBuffer[2048];
    UNICODE_STRING messageUnicode;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    HANDLE currentPid = PsGetCurrentProcessId();
    PUNICODE_STRING attackerPath = NULL;

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Open pipe
    status = ZwCreateFile(
        &pipeHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Get attacker process path
    NTSTATUS pathStatus = SeLocateProcessImageName(currentProcess, &attackerPath);
    PCWSTR attackerName = (NT_SUCCESS(pathStatus) && attackerPath) ?
        attackerPath->Buffer : L"Unknown";

    // Build JSON message
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));

    // Escape backslashes in registry path for JSON
    WCHAR escapedRegPath[1024];
    RtlZeroMemory(escapedRegPath, sizeof(escapedRegPath));

    if (RegPath && RegPath->Buffer && RegPath->Length > 0)
    {
        ULONG j = 0;
        for (ULONG i = 0; i < RegPath->Length / sizeof(WCHAR) && j < 1020; ++i)
        {
            if (RegPath->Buffer[i] == L'\\')
            {
                escapedRegPath[j++] = L'\\';
                escapedRegPath[j++] = L'\\';
            }
            else
            {
                escapedRegPath[j++] = RegPath->Buffer[i];
            }
        }
    }

    status = RtlStringCchPrintfW(
        messageBuffer,
        sizeof(messageBuffer) / sizeof(WCHAR),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%lld,\"attack_type\":\"REGISTRY_TAMPERING\",\"operation\":\"%s\"}",
        escapedRegPath,
        attackerName,
        (LONGLONG)(ULONG_PTR)currentPid,
        Operation
    );

    if (!NT_SUCCESS(status))
    {
        ZwClose(pipeHandle);
        if (attackerPath) ExFreePool(attackerPath);
        return status;
    }

    RtlInitUnicodeString(&messageUnicode, messageBuffer);

    // Write to pipe
    status = ZwWriteFile(
        pipeHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        messageUnicode.Buffer,
        messageUnicode.Length,
        NULL,
        NULL
    );

    ZwClose(pipeHandle);

    if (NT_SUCCESS(status))
    {
        DbgPrint("[Registry-Protection] Alert sent: PID %lld attempted %S on %wZ\r\n",
            (LONGLONG)(ULONG_PTR)currentPid,
            Operation,
            RegPath);
    }

    // Free allocated path
    if (attackerPath)
        ExFreePool(attackerPath);

    return status;
}

// Caller must allocate pRegistryPath->Buffer and set pRegistryPath->MaximumLength
BOOLEAN GetNameForRegistryObject(_Out_ PUNICODE_STRING pRegistryPath, _In_ PVOID pRegistryObject)
{
    if (!pRegistryPath || pRegistryPath->MaximumLength == 0 || !pRegistryPath->Buffer)
        return FALSE;

    if (!pRegistryObject || !MmIsAddressValid(pRegistryObject))
        return FALSE;

    NTSTATUS Status;
    ULONG ReturnLen = 0;
    POBJECT_NAME_INFORMATION NameInfo = NULL;

    // First call to get required length
    Status = ObQueryNameString(pRegistryObject, NULL, 0, &ReturnLen);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || ReturnLen == 0)
        return FALSE;

    NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLen, REG_TAG);
    if (!NameInfo)
        return FALSE;

    RtlZeroMemory(NameInfo, ReturnLen);

    Status = ObQueryNameString(pRegistryObject, NameInfo, ReturnLen, &ReturnLen);
    if (!NT_SUCCESS(Status) || NameInfo->Name.Length == 0)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    // Ensure destination buffer is large enough
    if (NameInfo->Name.Length > pRegistryPath->MaximumLength)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    // Copy into caller-provided UNICODE_STRING
    RtlCopyUnicodeString(pRegistryPath, &NameInfo->Name);

    ExFreePoolWithTag(NameInfo, REG_TAG);
    return TRUE;
}

// Case-insensitive substring search: returns TRUE if Pattern exists in Source
BOOLEAN UnicodeContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || Source->Length == 0 || !Pattern)
        return FALSE;

    UNICODE_STRING srcUp = { 0 }, patUp = { 0 };
    UNICODE_STRING pat;
    RtlInitUnicodeString(&pat, Pattern);

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, Source, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &pat, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcChars = srcUp.Length / sizeof(WCHAR);
    ULONG patChars = patUp.Length / sizeof(WCHAR);

    if (patChars > 0 && patChars <= srcChars)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;
        for (ULONG i = 0; i + patChars <= srcChars; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patChars * sizeof(WCHAR)))
            {
                found = TRUE;
                break;
            }
        }
    }

    RtlFreeUnicodeString(&srcUp);
    RtlFreeUnicodeString(&patUp);
    return found;
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING RegPath;
    RtlZeroMemory(&RegPath, sizeof(RegPath));
    RegPath.MaximumLength = sizeof(WCHAR) * 0x800;
    RegPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REG_TAG);
    if (!RegPath.Buffer)
        return Status;
    RegPath.Length = 0;

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (NotifyClass)
    {
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        if (pInfo && pInfo->Object)
        {
            if (GetNameForRegistryObject(&RegPath, pInfo->Object))
            {
                if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                {
                    RtlAppendUnicodeToString(&RegPath, L"\\");
                    RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                }

                if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH))
                {
                    // Send alert before denying
                    SendRegistryAlertToUserMode(&RegPath, L"DELETE_VALUE");
                    Status = STATUS_ACCESS_DENIED;
                }
            }
        }
        break;
    }

    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (pInfo && pInfo->Object)
        {
            if (GetNameForRegistryObject(&RegPath, pInfo->Object))
            {
                if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH))
                {
                    SendRegistryAlertToUserMode(&RegPath, L"DELETE_KEY");
                    Status = STATUS_ACCESS_DENIED;
                }
            }
        }
        break;
    }

    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (pInfo && pInfo->Object)
        {
            if (GetNameForRegistryObject(&RegPath, pInfo->Object))
            {
                if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                {
                    RtlAppendUnicodeToString(&RegPath, L"\\");
                    RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                }

                if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH))
                {
                    SendRegistryAlertToUserMode(&RegPath, L"SET_VALUE");
                    Status = STATUS_ACCESS_DENIED;
                }
            }
        }
        break;
    }

    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (pInfo && pInfo->Object)
        {
            if (GetNameForRegistryObject(&RegPath, pInfo->Object))
            {
                if (pInfo->NewName && pInfo->NewName->Length > 0)
                {
                    RtlAppendUnicodeToString(&RegPath, L"\\");
                    RtlAppendUnicodeStringToString(&RegPath, pInfo->NewName);
                }

                if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_SUBPATH))
                {
                    SendRegistryAlertToUserMode(&RegPath, L"RENAME_KEY");
                    Status = STATUS_ACCESS_DENIED;
                }
            }
        }
        break;
    }

    default:
        break;
    }

    ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
    return Status;
}
