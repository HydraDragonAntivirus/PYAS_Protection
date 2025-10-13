// Process.c - Process protection with user-mode alerting (FIXED + THREAD PROTECTION)
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver_Process.h"

PVOID obHandle;

#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Work item for deferred alerts
typedef struct _PROCESS_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING TargetPath;
    UNICODE_STRING AttackerPath;
    HANDLE TargetPid;
    HANDLE AttackerPid;
    WCHAR AttackType[64];
} PROCESS_ALERT_WORK_ITEM, * PPROCESS_ALERT_WORK_ITEM;

// Forward declarations
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process);
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process);
BOOLEAN IsProtectedThread(PETHREAD Thread);
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);
VOID ProcessAlertWorker(PVOID Context);
NTSTATUS QueueProcessAlertToUserMode(PEPROCESS TargetProcess, PEPROCESS AttackerProcess, PCWSTR AttackType);
OB_PREOP_CALLBACK_STATUS threadPreCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);

NTSTATUS ProcessDriverEntry()
{
    NTSTATUS status = ProtectProcess();
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Process-Protection] Initialized successfully\r\n");
    }
    else
    {
        DbgPrint("[Process-Protection] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

NTSTATUS ProtectProcess()
{
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg[2];  // Now we need 2: one for process, one for thread

    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 2;  // Changed from 1 to 2
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");

    // Process protection
    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;

    // Thread protection (NEW)
    opReg[1].ObjectType = PsThreadType;
    opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = (POB_PRE_OPERATION_CALLBACK)&threadPreCall;

    obReg.OperationRegistration = opReg;

    NTSTATUS status = ObRegisterCallbacks(&obReg, &obHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Process-Protection] ObRegisterCallbacks failed: 0x%X\r\n", status);
    }

    return status;
}

// Worker routine running at PASSIVE_LEVEL
VOID ProcessAlertWorker(PVOID Context)
{
    PPROCESS_ALERT_WORK_ITEM workItem = (PPROCESS_ALERT_WORK_ITEM)Context;
    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    WCHAR messageBuffer[2048];

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
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    PCWSTR targetName = workItem->TargetPath.Buffer ? workItem->TargetPath.Buffer : L"Unknown";
    PCWSTR attackerName = workItem->AttackerPath.Buffer ? workItem->AttackerPath.Buffer : L"Unknown";

    // Build JSON message
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%lld,\"attack_type\":\"%s\",\"target_pid\":%lld}",
        targetName,
        attackerName,
        (LONGLONG)(ULONG_PTR)workItem->AttackerPid,
        workItem->AttackType,
        (LONGLONG)(ULONG_PTR)workItem->TargetPid
    );

    if (!NT_SUCCESS(status))
    {
        ZwClose(pipeHandle);
        goto Cleanup;
    }

    SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);

    // Write to pipe
    status = ZwWriteFile(
        pipeHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        messageBuffer,
        (ULONG)messageLength,
        NULL,
        NULL
    );

    ZwClose(pipeHandle);

    if (NT_SUCCESS(status))
    {
        DbgPrint("[Process-Protection] Alert sent: PID %lld attacked PID %lld (%s)\r\n",
            (LONGLONG)(ULONG_PTR)workItem->AttackerPid,
            (LONGLONG)(ULONG_PTR)workItem->TargetPid,
            workItem->AttackType);
    }

Cleanup:
    // Free allocated strings
    if (workItem->TargetPath.Buffer)
        ExFreePool(workItem->TargetPath.Buffer);
    if (workItem->AttackerPath.Buffer)
        ExFreePool(workItem->AttackerPath.Buffer);

    ExFreePoolWithTag(workItem, 'crpA');
}

NTSTATUS QueueProcessAlertToUserMode(
    PEPROCESS TargetProcess,
    PEPROCESS AttackerProcess,
    PCWSTR AttackType
)
{
    PPROCESS_ALERT_WORK_ITEM workItem;
    PUNICODE_STRING targetPath = NULL;
    PUNICODE_STRING attackerPath = NULL;
    NTSTATUS status;

    // Allocate work item
    workItem = (PPROCESS_ALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(PROCESS_ALERT_WORK_ITEM),
        'crpA'
    );

    if (!workItem)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(workItem, sizeof(PROCESS_ALERT_WORK_ITEM));

    // Get process paths
    status = SeLocateProcessImageName(TargetProcess, &targetPath);
    if (NT_SUCCESS(status) && targetPath && targetPath->Buffer && targetPath->Length > 0)
    {
        workItem->TargetPath.Length = targetPath->Length;
        workItem->TargetPath.MaximumLength = targetPath->Length + sizeof(WCHAR);
        workItem->TargetPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->TargetPath.MaximumLength,
            'crpA'
        );

        if (workItem->TargetPath.Buffer)
        {
            RtlCopyMemory(workItem->TargetPath.Buffer, targetPath->Buffer, targetPath->Length);
            workItem->TargetPath.Buffer[targetPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    status = SeLocateProcessImageName(AttackerProcess, &attackerPath);
    if (NT_SUCCESS(status) && attackerPath && attackerPath->Buffer && attackerPath->Length > 0)
    {
        workItem->AttackerPath.Length = attackerPath->Length;
        workItem->AttackerPath.MaximumLength = attackerPath->Length + sizeof(WCHAR);
        workItem->AttackerPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->AttackerPath.MaximumLength,
            'crpA'
        );

        if (workItem->AttackerPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackerPath.Buffer, attackerPath->Buffer, attackerPath->Length);
            workItem->AttackerPath.Buffer[attackerPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Free the allocated paths from SeLocateProcessImageName
    if (targetPath)
        ExFreePool(targetPath);
    if (attackerPath)
        ExFreePool(attackerPath);

    // Copy PIDs and attack type
    workItem->TargetPid = PsGetProcessId(TargetProcess);
    workItem->AttackerPid = PsGetProcessId(AttackerProcess);
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType);

    // Queue work item
    ExInitializeWorkItem(&workItem->WorkItem, ProcessAlertWorker, workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}

// NEW: Thread protection callback
OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    PETHREAD targetThread = (PETHREAD)pOperationInformation->Object;
    PEPROCESS targetProc = NULL;
    PEPROCESS currentProc = PsGetCurrentProcess();
    BOOLEAN alertSent = FALSE;

    if (!targetThread)
        return OB_PREOP_SUCCESS;

    // Get the process that owns this thread
    targetProc = PsGetThreadProcess(targetThread);
    if (!targetProc)
        return OB_PREOP_SUCCESS;

    __try
    {
        // Check if this thread belongs to a protected process
        if (IsProtectedProcessByPath(targetProc) || IsProtectedProcessByImageName(targetProc))
        {
            // Allow the protected process to manage its own threads
            if (targetProc == currentProc)
            {
                return OB_PREOP_SUCCESS;
            }
            // Handle CREATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

                // Check for thread suspension or termination attempts
                if ((orig & THREAD_SUSPEND_RESUME) ||
                    (orig & THREAD_TERMINATE) ||
                    (orig & THREAD_SET_CONTEXT))
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"THREAD_SUSPEND");
                        alertSent = TRUE;
                    }
                }

                // Strip all dangerous thread access rights
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_INFORMATION;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_THREAD_TOKEN;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_IMPERSONATE;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_DIRECT_IMPERSONATION;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_LIMITED_INFORMATION;
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_QUERY_LIMITED_INFORMATION;

                // Allow only basic query rights
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (THREAD_QUERY_INFORMATION | SYNCHRONIZE);
            }

            // Handle DUPLICATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

                if ((orig & THREAD_SUSPEND_RESUME) ||
                    (orig & THREAD_TERMINATE) ||
                    (orig & THREAD_SET_CONTEXT))
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"THREAD_HIJACK");
                        alertSent = TRUE;
                    }
                }

                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_INFORMATION;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_THREAD_TOKEN;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_IMPERSONATE;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_DIRECT_IMPERSONATION;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_LIMITED_INFORMATION;
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_QUERY_LIMITED_INFORMATION;

                // Allow only basic query rights
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (THREAD_QUERY_INFORMATION | SYNCHRONIZE);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Thread-Protection] Exception in threadPreCall: 0x%X\r\n", GetExceptionCode());
    }

    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    HANDLE pidHandle = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
    PEPROCESS targetProc = NULL;
    PEPROCESS currentProc = PsGetCurrentProcess();
    BOOLEAN alertSent = FALSE;

    if (!pidHandle)
        return OB_PREOP_SUCCESS;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pidHandle, &targetProc)))
        return OB_PREOP_SUCCESS;

    __try
    {
        // Check if target process is protected
        if (IsProtectedProcessByPath(targetProc) || IsProtectedProcessByImageName(targetProc))
        {
            // Handle CREATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

                // Check for dangerous access requests
                if ((orig & PROCESS_TERMINATE) ||
                    (orig & PROCESS_VM_WRITE) ||
                    (orig & PROCESS_VM_OPERATION) ||
                    (orig == PROCESS_TERMINATE_0) ||
                    (orig == PROCESS_TERMINATE_1) ||
                    (orig == PROCESS_KILL_F))
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"PROCESS_KILL");
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
                ULONG orig = (ULONG)pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

                if ((orig & PROCESS_TERMINATE) ||
                    (orig & PROCESS_VM_WRITE) ||
                    (orig & PROCESS_VM_OPERATION))
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"HANDLE_HIJACK");
                        alertSent = TRUE;
                    }
                }

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
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Process-Protection] Exception in preCall: 0x%X\r\n", GetExceptionCode());
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
        "HydraDragonAntivirusLauncher.exe",
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
    {
        ObUnRegisterCallbacks(obHandle);
        obHandle = NULL;
    }
    DbgPrint("[Process-Protection] Unloaded\r\n");
    return STATUS_SUCCESS;
}
