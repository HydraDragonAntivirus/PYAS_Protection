// Process.c - Process & Thread protection with user-mode alerting (Safer version)
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
BOOLEAN IsProtectedThread(PETHREAD Thread);
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);
VOID ProcessAlertWorker(PVOID Context);
NTSTATUS QueueProcessAlertToUserMode(PEPROCESS TargetProcess, PEPROCESS AttackerProcess, PCWSTR AttackType);
OB_PREOP_CALLBACK_STATUS threadPreCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);
OB_PREOP_CALLBACK_STATUS preCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);

//
// Safety masks
//
#define PROCESS_SAFE_MASK (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define PROCESS_DANGEROUS_MASK (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | \
                                PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION | \
                                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | \
                                PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_SET_LIMITED_INFORMATION)

#define THREAD_SAFE_MASK (THREAD_QUERY_INFORMATION | SYNCHRONIZE)
#define THREAD_DANGEROUS_MASK (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | \
                               THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                               THREAD_DIRECT_IMPERSONATION)

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
    OB_OPERATION_REGISTRATION opReg[2];  // Process + Thread

    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 2;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");

    // Process protection
    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;
    opReg[0].PostOperation = NULL;

    // Thread protection
    opReg[1].ObjectType = PsThreadType;
    opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = (POB_PRE_OPERATION_CALLBACK)&threadPreCall;
    opReg[1].PostOperation = NULL;

    obReg.OperationRegistration = opReg;

    NTSTATUS status = ObRegisterCallbacks(&obReg, &obHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Process-Protection] ObRegisterCallbacks failed: 0x%X\r\n", status);
    }
    else
    {
        DbgPrint("[Process-Protection] ObRegisterCallbacks succeeded\r\n");
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

    if (!workItem)
        return;

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Open pipe (async worker - safe to call Zw APIs)
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
        DbgPrint("[Process-Protection] Failed to open user pipe: 0x%X\r\n", status);
        goto Cleanup;
    }

    PCWSTR targetName = workItem->TargetPath.Buffer ? workItem->TargetPath.Buffer : L"Unknown";
    PCWSTR attackerName = workItem->AttackerPath.Buffer ? workItem->AttackerPath.Buffer : L"Unknown";

    // Build JSON message
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%llu,\"attack_type\":\"%s\",\"target_pid\":%llu}",
        targetName,
        attackerName,
        (unsigned long long)(ULONG_PTR)workItem->AttackerPid,
        workItem->AttackType,
        (unsigned long long)(ULONG_PTR)workItem->TargetPid
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Process-Protection] Failed to format alert message: 0x%X\r\n", status);
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
        DbgPrint("[Process-Protection] Alert sent: PID %llu attacked PID %llu (%ws)\r\n",
            (unsigned long long)(ULONG_PTR)workItem->AttackerPid,
            (unsigned long long)(ULONG_PTR)workItem->TargetPid,
            workItem->AttackType);
    }
    else
    {
        DbgPrint("[Process-Protection] ZwWriteFile failed: 0x%X\r\n", status);
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

// Thread protection callback (safer)
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
        if (IsProtectedProcessByPath(targetProc))
        {
            // Allow the protected process to manage its own threads
            if (targetProc == currentProc || PsGetProcessId(targetProc) == PsGetProcessId(currentProc))
            {
                goto Done; // don't dereference: PsGetThreadProcess does not return a referenced object
            }

            // CREATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
                ULONG* pDesired = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
                ULONG before = *pDesired;

                // If caller requested dangerous bits - queue alert
                if (orig & THREAD_DANGEROUS_MASK)
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"THREAD_SUSPEND");
                        alertSent = TRUE;
                    }
                }

                // Remove dangerous bits, but leave safe mask available
                *pDesired &= ~THREAD_DANGEROUS_MASK;
                *pDesired &= THREAD_SAFE_MASK;

                DbgPrint("[Thread-Protection] CREATE: pid=%llu orig=0x%X before=0x%X after=0x%X\n",
                    (unsigned long long)(ULONG_PTR)PsGetProcessId(currentProc),
                    orig, before, *pDesired);
            }

            // DUPLICATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
                ULONG* pDesired = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
                ULONG before = *pDesired;

                if (orig & THREAD_DANGEROUS_MASK)
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"THREAD_HIJACK");
                        alertSent = TRUE;
                    }
                }

                *pDesired &= ~THREAD_DANGEROUS_MASK;
                *pDesired &= THREAD_SAFE_MASK;

                DbgPrint("[Thread-Protection] DUP: pid=%llu orig=0x%X before=0x%X after=0x%X\n",
                    (unsigned long long)(ULONG_PTR)PsGetProcessId(currentProc),
                    orig, before, *pDesired);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Thread-Protection] Exception in threadPreCall: 0x%X\r\n", GetExceptionCode());
    }

Done:
    // PsGetThreadProcess does NOT return a referenced object; do NOT call ObDereferenceObject here.
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
        if (IsProtectedProcessByPath(targetProc))
        {
            // Allow the protected process to manage itself
            if (targetProc == currentProc || PsGetProcessId(targetProc) == PsGetProcessId(currentProc))
            {
                // Jump to cleanup so we only dereference targetProc once (PsLookupProcessByProcessId returned a referenced object)
                goto Cleanup;
            }

            // CREATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
                ULONG* pDesired = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
                ULONG before = *pDesired;

                // If caller requested any dangerous bits, queue an alert
                if (orig & PROCESS_DANGEROUS_MASK)
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"PROCESS_KILL");
                        alertSent = TRUE;
                    }
                }

                // Remove dangerous bits and cap to safe mask (do not zero-out completely)
                *pDesired &= ~PROCESS_DANGEROUS_MASK;
                *pDesired &= PROCESS_SAFE_MASK;

                DbgPrint("[Process-Protection] CREATE: target=%llu caller=%llu orig=0x%X before=0x%X after=0x%X\n",
                    (unsigned long long)(ULONG_PTR)PsGetProcessId(targetProc),
                    (unsigned long long)(ULONG_PTR)PsGetProcessId(currentProc),
                    orig, before, *pDesired);
            }

            // DUPLICATE operation
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                ULONG orig = (ULONG)pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
                ULONG* pDesired = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
                ULONG before = *pDesired;

                if (orig & PROCESS_DANGEROUS_MASK)
                {
                    if (!alertSent)
                    {
                        QueueProcessAlertToUserMode(targetProc, currentProc, L"HANDLE_HIJACK");
                        alertSent = TRUE;
                    }
                }

                *pDesired &= ~PROCESS_DANGEROUS_MASK;
                *pDesired &= PROCESS_SAFE_MASK;

                DbgPrint("[Process-Protection] DUP: target=%llu caller=%llu orig=0x%X before=0x%X after=0x%X\n",
                    (unsigned long long)(ULONG_PTR)PsGetProcessId(targetProc),
                    (unsigned long long)(ULONG_PTR)PsGetProcessId(currentProc),
                    orig, before, *pDesired);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Process-Protection] Exception in preCall: 0x%X\r\n", GetExceptionCode());
    }

Cleanup:
    if (targetProc)
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

    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer)
    {
        if (pImageName)
            ExFreePool(pImageName);
        return FALSE;
    }

    // Patterns to match (substring-based). Be as specific as possible to avoid accidental matches.
    static const PCWSTR patterns[] = {
        L"\\HydraDragonAntivirus\\hydradragon\\Owlyshield Service\\owlyshield_ransom.exe",
        L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe",
        L"\\Sanctum\\sanctum_ppl_runner.exe",
        L"\\sanctum\\app.exe",
        L"\\sanctum\\server.exe",
        L"\\sanctum\\um_engine.exe"
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
