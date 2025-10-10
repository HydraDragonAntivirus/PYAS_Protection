// Process.c - Process protection with user-mode alerting
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver_Process.h"

PVOID obHandle;

#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Forward declarations
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process);
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process);
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);
NTSTATUS SendProcessAlertToUserMode(PEPROCESS TargetProcess, PEPROCESS AttackerProcess, PCWSTR AttackType);

// Entry / register
NTSTATUS ProcessDriverEntry()
{
    ProtectProcess();
    return STATUS_SUCCESS;
}

NTSTATUS ProtectProcess()
{
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");

    // register for process handle create & duplicate
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;

    obReg.OperationRegistration = &opReg;

    return ObRegisterCallbacks(&obReg, &obHandle);
}

NTSTATUS SendProcessAlertToUserMode(
    PEPROCESS TargetProcess,
    PEPROCESS AttackerProcess,
    PCWSTR AttackType
)
{
    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    WCHAR messageBuffer[2048];
    UNICODE_STRING messageUnicode;
    PUNICODE_STRING targetPath = NULL;
    PUNICODE_STRING attackerPath = NULL;
    HANDLE targetPid = PsGetProcessId(TargetProcess);
    HANDLE attackerPid = PsGetProcessId(AttackerProcess);

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

    // Get process paths
    status = SeLocateProcessImageName(TargetProcess, &targetPath);
    NTSTATUS attackerStatus = SeLocateProcessImageName(AttackerProcess, &attackerPath);

    PCWSTR targetName = (NT_SUCCESS(status) && targetPath) ? targetPath->Buffer : L"Unknown";
    PCWSTR attackerName = (NT_SUCCESS(attackerStatus) && attackerPath) ? attackerPath->Buffer : L"Unknown";

    // Build JSON message using RtlStringCchPrintfW
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    status = RtlStringCchPrintfW(
        messageBuffer,
        sizeof(messageBuffer) / sizeof(WCHAR),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%lld,\"attack_type\":\"%s\",\"target_pid\":%lld}",
        targetName,
        attackerName,
        (LONGLONG)(ULONG_PTR)attackerPid,
        AttackType,
        (LONGLONG)(ULONG_PTR)targetPid
    );

    if (!NT_SUCCESS(status))
    {
        ZwClose(pipeHandle);
        if (targetPath) ExFreePool(targetPath);
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
        DbgPrint("[Process-Protection] Alert sent: PID %lld attacked PID %lld (%s)\r\n",
            (LONGLONG)(ULONG_PTR)attackerPid,
            (LONGLONG)(ULONG_PTR)targetPid,
            AttackType);
    }

    // Free allocated paths
    if (targetPath)
        ExFreePool(targetPath);
    if (attackerPath)
        ExFreePool(attackerPath);

    return status;
}

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // get process id from the object (object is EPROCESS)
    HANDLE pidHandle = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
    PEPROCESS targetProc = NULL;
    PEPROCESS currentProc = PsGetCurrentProcess();
    BOOLEAN alertSent = FALSE;

    if (!pidHandle)
        return OB_PREOP_SUCCESS;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pidHandle, &targetProc)))
        return OB_PREOP_SUCCESS;

    // Check if target process is protected
    if (IsProtectedProcessByPath(targetProc) || IsProtectedProcessByImageName(targetProc))
    {
        // Handle CREATE operation
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            // use CreateHandleInformation for CREATE
            ULONG orig = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

            // Check for dangerous access requests
            if ((orig & PROCESS_TERMINATE) ||
                (orig & PROCESS_VM_WRITE) ||
                (orig & PROCESS_VM_OPERATION) ||
                (orig == PROCESS_TERMINATE_0) ||
                (orig == PROCESS_TERMINATE_1) ||
                (orig == PROCESS_KILL_F))
            {
                // Send alert before blocking
                if (!alertSent)
                {
                    SendProcessAlertToUserMode(targetProc, currentProc, L"PROCESS_KILL");
                    alertSent = TRUE;
                }
            }

            // Strip all dangerous access rights
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_SESSIONID;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_PROCESS;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_LIMITED_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

            // Handle special cases
            if ((orig == PROCESS_TERMINATE_0) ||
                (orig == PROCESS_TERMINATE_1) ||
                (orig == PROCESS_KILL_F))
            {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x0;
            }
            if (orig == 0x1041)
            {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL;
            }
        }

        // Handle DUPLICATE operation
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            // use DuplicateHandleInformation for DUPLICATE
            ULONG orig = (ULONG)pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

            // Check for dangerous access
            if ((orig & PROCESS_TERMINATE) ||
                (orig & PROCESS_VM_WRITE) ||
                (orig & PROCESS_VM_OPERATION))
            {
                if (!alertSent)
                {
                    SendProcessAlertToUserMode(targetProc, currentProc, L"HANDLE_HIJACK");
                    alertSent = TRUE;
                }
            }

            // Strip dangerous rights
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_SESSIONID;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_PROCESS;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_LIMITED_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

            if ((orig == PROCESS_TERMINATE_0) ||
                (orig == PROCESS_TERMINATE_1) ||
                (orig == PROCESS_KILL_F))
            {
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0x0;
            }
            if (orig == 0x1041)
            {
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL;
            }
        }
    }

    ObDereferenceObject(targetProc);
    return OB_PREOP_SUCCESS;
}

// Checks if the process image full path contains any of our interesting substrings.
// Note: SeLocateProcessImageName allocates the returned UNICODE_STRING buffer; free it with ExFreePool.
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process)
{
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    // SeLocateProcessImageName returns allocated UNICODE_STRING (free with ExFreePool)
    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer)
    {
        if (pImageName)
            ExFreePool(pImageName);
        return FALSE;
    }

    // Patterns to match (not full hardcoded absolute paths; substring-based)
    static const PCWSTR patterns[] = {
        L"\\HydraDragonAntivirus\\",
        L"\\hydradragon\\",
        L"\\Owlyshield Service\\",
        L"\\owlyshield_ransom.exe",
        L"\\Sanctum\\",
        L"\\sanctum_ppl_runner.exe",
        L"\\app.exe",
        L"\\server.exe",
        L"\\um_engine.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(patterns); ++i)
    {
        if (UnicodeStringContainsInsensitive(pImageName, patterns[i]))
        {
            result = TRUE;
            break;
        }
    }

    ExFreePool(pImageName);
    return result;
}

// Fallback: still protect by image file name (PsGetProcessImageFileName returns ANSI 15-char name)
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process)
{
    PUCHAR name = PsGetProcessImageFileName(Process);
    if (!name)
        return FALSE;

    // list of exact filenames we also protect
    const char* names[] = {
        "HydraDragonAntivirusService.exe",
        "owlyshield_ransom.exe",
        "sanctum_ppl_runner.exe",
        "app.exe",
        "server.exe",
        "um_engine.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(names); ++i)
    {
        if (_stricmp((const char*)name, names[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Case-insensitive substring search using RtlUpcaseUnicodeString.
// Returns TRUE if 'Pattern' is found inside 'Source' (case-insensitive).
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || !Pattern)
        return FALSE;

    UNICODE_STRING srcU = *Source;
    UNICODE_STRING patU;
    RtlInitUnicodeString(&patU, Pattern);

    // Make uppercase copies (RtlUpcaseUnicodeString will allocate if third param TRUE)
    UNICODE_STRING srcUp, patUp;
    RtlZeroMemory(&srcUp, sizeof(srcUp));
    RtlZeroMemory(&patUp, sizeof(patUp));

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, &srcU, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &patU, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcLen = srcUp.Length / sizeof(WCHAR);
    ULONG patLen = patUp.Length / sizeof(WCHAR);

    if (patLen > 0 && patLen <= srcLen)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;

        for (ULONG i = 0; i + patLen <= srcLen; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patLen * sizeof(WCHAR)))
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

NTSTATUS ProcessDriverUnload()
{
    if (obHandle)
        ObUnRegisterCallbacks(obHandle);
    return STATUS_SUCCESS;
}
