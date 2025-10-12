// Process.c - Process protection with user-mode alerting (FIXED - Windows 10 x64)
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver.h"
#include "Driver_Process.h"

PVOID obHandle;

#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Work item for deferred alerts
typedef struct _PROCESS_ALERT_WORK_ITEM {
    PIO_WORKITEM IoWorkItem;
    UNICODE_STRING TargetPath;
    UNICODE_STRING AttackerPath;
    HANDLE TargetPid;
    HANDLE AttackerPid;
    WCHAR AttackType[64];
} PROCESS_ALERT_WORK_ITEM, * PPROCESS_ALERT_WORK_ITEM;

// Forward declarations
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process);
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process);
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);
VOID ProcessAlertWorker(PDEVICE_OBJECT DeviceObject, PVOID Context);
NTSTATUS QueueProcessAlertToUserMode(PEPROCESS TargetProcess, PEPROCESS AttackerProcess, PCWSTR AttackType);

// Helper function to check if process is System (PID 4)
BOOLEAN IsSystemProcess(PEPROCESS Process)
{
    HANDLE pid = PsGetProcessId(Process);
    return ((ULONG_PTR)pid == 4);
}

NTSTATUS ProcessDriverEntry(PDEVICE_OBJECT DeviceObject)
{
    g_DeviceObject = DeviceObject;

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
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");

    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;

    obReg.OperationRegistration = &opReg;

    NTSTATUS status = ObRegisterCallbacks(&obReg, &obHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Process-Protection] ObRegisterCallbacks failed: 0x%X\r\n", status);
    }

    return status;
}

// Worker routine running at PASSIVE_LEVEL
VOID ProcessAlertWorker(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

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
        ExFreePoolWithTag(workItem->TargetPath.Buffer, 'crpA');
    if (workItem->AttackerPath.Buffer)
        ExFreePoolWithTag(workItem->AttackerPath.Buffer, 'crpA');

    // Free work item
    if (workItem->IoWorkItem)
        IoFreeWorkItem(workItem->IoWorkItem);

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

    if (!g_DeviceObject)
        return STATUS_DEVICE_NOT_READY;

    // Allocate work item structure
    workItem = (PPROCESS_ALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(PROCESS_ALERT_WORK_ITEM),
        'crpA'
    );

    if (!workItem)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(workItem, sizeof(PROCESS_ALERT_WORK_ITEM));

    // Allocate IO work item
    workItem->IoWorkItem = IoAllocateWorkItem(g_DeviceObject);
    if (!workItem->IoWorkItem)
    {
        ExFreePoolWithTag(workItem, 'crpA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

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

    // Queue work item (modern API)
    IoQueueWorkItem(
        workItem->IoWorkItem,
        ProcessAlertWorker,
        DelayedWorkQueue,
        workItem
    );

    return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Check IRQL - only process at PASSIVE_LEVEL
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;
    PEPROCESS currentProc = PsGetCurrentProcess();
    HANDLE targetPid = PsGetProcessId(targetProc);
    BOOLEAN alertSent = FALSE;

    if (!targetPid)
        return OB_PREOP_SUCCESS;

    __try
    {
        // CRITICAL: Allow self-access (process accessing its own handles)
        if (targetProc == currentProc)
            return OB_PREOP_SUCCESS;

        // CRITICAL: Allow system processes full access
        if (IsSystemProcess(currentProc))
            return OB_PREOP_SUCCESS;

        // Check if target process is protected
        if (!IsProtectedProcessByPath(targetProc) && !IsProtectedProcessByImageName(targetProc))
            return OB_PREOP_SUCCESS;

        // Handle CREATE operation
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            ACCESS_MASK originalAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
            ACCESS_MASK* desiredAccess = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

            // Define dangerous access rights
            ACCESS_MASK dangerousAccess =
                PROCESS_TERMINATE |
                PROCESS_VM_WRITE |
                PROCESS_VM_OPERATION |
                PROCESS_CREATE_THREAD |
                PROCESS_SET_SESSIONID |
                PROCESS_DUP_HANDLE |
                PROCESS_CREATE_PROCESS |
                PROCESS_SET_QUOTA |
                PROCESS_SET_INFORMATION |
                PROCESS_SUSPEND_RESUME |
                PROCESS_SET_LIMITED_INFORMATION;

            // Check for dangerous access requests and send alert
            if ((originalAccess & PROCESS_TERMINATE) ||
                (originalAccess & PROCESS_VM_WRITE) ||
                (originalAccess & PROCESS_VM_OPERATION) ||
                (originalAccess == PROCESS_TERMINATE_0) ||
                (originalAccess == PROCESS_TERMINATE_1) ||
                (originalAccess == PROCESS_KILL_F))
            {
                if (!alertSent)
                {
                    QueueProcessAlertToUserMode(targetProc, currentProc, L"PROCESS_KILL");
                    alertSent = TRUE;
                }
            }

            // Strip dangerous access rights
            *desiredAccess &= ~dangerousAccess;

            // CRITICAL: Never set to 0 - always keep minimal safe access
            if (*desiredAccess == 0)
            {
                *desiredAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
            }

            // Keep safe standard rights
            *desiredAccess |= SYNCHRONIZE;

            // Handle special cases
            if ((originalAccess == PROCESS_TERMINATE_0) ||
                (originalAccess == PROCESS_TERMINATE_1) ||
                (originalAccess == PROCESS_KILL_F))
            {
                *desiredAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
            }

            if (originalAccess == 0x1041)
            {
                *desiredAccess = STANDARD_RIGHTS_READ | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
            }
        }

        // Handle DUPLICATE operation
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            ACCESS_MASK originalAccess = pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
            ACCESS_MASK* desiredAccess = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

            ACCESS_MASK dangerousAccess =
                PROCESS_TERMINATE |
                PROCESS_VM_WRITE |
                PROCESS_VM_OPERATION |
                PROCESS_CREATE_THREAD |
                PROCESS_SET_SESSIONID |
                PROCESS_DUP_HANDLE |
                PROCESS_CREATE_PROCESS |
                PROCESS_SET_QUOTA |
                PROCESS_SET_INFORMATION |
                PROCESS_SUSPEND_RESUME |
                PROCESS_SET_LIMITED_INFORMATION;

            if ((originalAccess & PROCESS_TERMINATE) ||
                (originalAccess & PROCESS_VM_WRITE) ||
                (originalAccess & PROCESS_VM_OPERATION))
            {
                if (!alertSent)
                {
                    QueueProcessAlertToUserMode(targetProc, currentProc, L"HANDLE_HIJACK");
                    alertSent = TRUE;
                }
            }

            // Strip dangerous access rights
            *desiredAccess &= ~dangerousAccess;

            // CRITICAL: Never set to 0 - always keep minimal safe access
            if (*desiredAccess == 0)
            {
                *desiredAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
            }

            // Keep safe standard rights
            *desiredAccess |= SYNCHRONIZE;

            if ((originalAccess == PROCESS_TERMINATE_0) ||
                (originalAccess == PROCESS_TERMINATE_1) ||
                (originalAccess == PROCESS_KILL_F))
            {
                *desiredAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
            }

            if (originalAccess == 0x1041)
            {
                *desiredAccess = STANDARD_RIGHTS_READ | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Process-Protection] Exception in preCall: 0x%X\r\n", GetExceptionCode());
    }

    return OB_PREOP_SUCCESS;
}

// Checks if the process image full path contains any of our interesting substrings.
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

    // Patterns to match (substring-based)
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

// Fallback: protect by image file name
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process)
{
    PUCHAR name = PsGetProcessImageFileName(Process);
    if (!name)
        return FALSE;

    // List of exact filenames we also protect
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

// Case-insensitive substring search
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || !Pattern)
        return FALSE;

    UNICODE_STRING srcU = *Source;
    UNICODE_STRING patU;
    RtlInitUnicodeString(&patU, Pattern);

    // Make uppercase copies
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

    g_DeviceObject = NULL;

    DbgPrint("[Process-Protection] Unloaded\r\n");
    return STATUS_SUCCESS;
}
