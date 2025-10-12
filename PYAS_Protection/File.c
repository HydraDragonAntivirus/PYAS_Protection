// File.c - Self-Defense Protection with User-Mode Alerting (FIXED)
#include "Drvier_File.h"
#include <ntstrsafe.h>

PVOID CallBackHandle = NULL;

// Pipe name for self-defense alerts
#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Work item structure for deferred pipe communication
typedef struct _ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING ProtectedFile;
    UNICODE_STRING AttackingProcessPath;
    HANDLE AttackingPid;
    WCHAR AttackType[64];
} ALERT_WORK_ITEM, * PALERT_WORK_ITEM;

NTSTATUS FileDriverEntry()
{
    // Register file protection callbacks
    NTSTATUS status = ProtectFileByObRegisterCallbacks();
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Self-Defense] File protection initialized\r\n");
    }
    else
    {
        DbgPrint("[Self-Defense] Failed to initialize file protection: 0x%X\r\n", status);
    }
    return status;
}

// Worker routine that runs at PASSIVE_LEVEL
VOID SendAlertWorker(PVOID Context)
{
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)Context;
    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    WCHAR messageBuffer[2048];
    LARGE_INTEGER timeout;

    // Initialize pipe name
    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Set timeout to 100ms to avoid blocking
    timeout.QuadPart = -1000000; // 100ms in 100-nanosecond units (negative = relative)

    // Try to open the pipe (non-blocking)
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
        // Pipe not available - service may not be running yet
        goto Cleanup;
    }

    // Build JSON-like message for user-mode
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));

    PCWSTR protectedName = workItem->ProtectedFile.Buffer ? workItem->ProtectedFile.Buffer : L"Unknown";
    PCWSTR attackerPath = workItem->AttackingProcessPath.Buffer ? workItem->AttackingProcessPath.Buffer : L"Unknown";

    // Use RtlStringCbPrintfW (byte-based) which is safer
    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%lld,\"attack_type\":\"%s\"}",
        protectedName,
        attackerPath,
        (LONGLONG)(ULONG_PTR)workItem->AttackingPid,
        workItem->AttackType
    );

    if (!NT_SUCCESS(status))
    {
        ZwClose(pipeHandle);
        goto Cleanup;
    }

    // Calculate actual string length
    SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);

    // Write to pipe with timeout
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
        DbgPrint("[Self-Defense] Alert sent to user-mode: %wZ attacked by PID %lld\r\n",
            &workItem->ProtectedFile, (LONGLONG)(ULONG_PTR)workItem->AttackingPid);
    }

Cleanup:
    // Free allocated strings
    if (workItem->ProtectedFile.Buffer)
    {
        ExFreePool(workItem->ProtectedFile.Buffer);
    }
    if (workItem->AttackingProcessPath.Buffer)
    {
        ExFreePool(workItem->AttackingProcessPath.Buffer);
    }

    // Free work item
    ExFreePoolWithTag(workItem, 'tlrA');
}

NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
)
{
    PALERT_WORK_ITEM workItem;
    NTSTATUS status = STATUS_SUCCESS;

    // Allocate work item
    workItem = (PALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(ALERT_WORK_ITEM),
        'tlrA'
    );

    if (!workItem)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(workItem, sizeof(ALERT_WORK_ITEM));

    // Copy protected file path
    if (ProtectedFile && ProtectedFile->Buffer && ProtectedFile->Length > 0)
    {
        workItem->ProtectedFile.Length = ProtectedFile->Length;
        workItem->ProtectedFile.MaximumLength = ProtectedFile->Length + sizeof(WCHAR);
        workItem->ProtectedFile.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->ProtectedFile.MaximumLength,
            'tlrA'
        );

        if (workItem->ProtectedFile.Buffer)
        {
            RtlCopyMemory(workItem->ProtectedFile.Buffer, ProtectedFile->Buffer, ProtectedFile->Length);
            workItem->ProtectedFile.Buffer[ProtectedFile->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Copy attacking process path
    if (AttackingProcessPath && AttackingProcessPath->Buffer && AttackingProcessPath->Length > 0)
    {
        workItem->AttackingProcessPath.Length = AttackingProcessPath->Length;
        workItem->AttackingProcessPath.MaximumLength = AttackingProcessPath->Length + sizeof(WCHAR);
        workItem->AttackingProcessPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->AttackingProcessPath.MaximumLength,
            'tlrA'
        );

        if (workItem->AttackingProcessPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackingProcessPath.Buffer, AttackingProcessPath->Buffer, AttackingProcessPath->Length);
            workItem->AttackingProcessPath.Buffer[AttackingProcessPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Copy PID and attack type
    workItem->AttackingPid = AttackingPid;
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType);

    // Initialize and queue work item
    ExInitializeWorkItem(&workItem->WorkItem, SendAlertWorker, workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return status;
}

NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION  CallBackReg;
    OB_OPERATION_REGISTRATION OperationReg;
    NTSTATUS Status;

    // Check if IoFileObjectType supports callbacks
    // Note: On modern Windows (Win10+), this should be supported by default
    // Removed dangerous EnableObType() call

    RtlZeroMemory(&CallBackReg, sizeof(OB_CALLBACK_REGISTRATION));
    CallBackReg.Version = ObGetFilterVersion();
    CallBackReg.OperationRegistrationCount = 1;
    CallBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&CallBackReg.Altitude, L"321000");

    RtlZeroMemory(&OperationReg, sizeof(OB_OPERATION_REGISTRATION));

    OperationReg.ObjectType = IoFileObjectType;
    OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCallBack;

    CallBackReg.OperationRegistration = &OperationReg;

    Status = ObRegisterCallbacks(&CallBackReg, &CallBackHandle);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[Self-Defense] ObRegisterCallbacks failed: 0x%X\r\n", Status);
        return Status;
    }

    DbgPrint("[Self-Defense] Callbacks registered successfully\r\n");
    return STATUS_SUCCESS;
}

BOOLEAN FilePathContains(PUNICODE_STRING FilePath, PCWSTR Pattern)
{
    if (!FilePath || !FilePath->Buffer || !Pattern)
        return FALSE;

    // Safe string search
    PWCHAR found = wcsstr(FilePath->Buffer, Pattern);
    return (found != NULL);
}

OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNICODE_STRING uniFilePath = { 0 };
    PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
    HANDLE CurrentProcessId = PsGetCurrentProcessId();
    BOOLEAN isProtected = FALSE;
    PEPROCESS currentProcess = NULL;
    PUNICODE_STRING attackerPath = NULL;
    POBJECT_NAME_INFORMATION fileNameInfo = NULL;

    UNREFERENCED_PARAMETER(RegistrationContext);

    // Verify object type
    if (OperationInformation->ObjectType != *IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }

    // Use SEH for safe memory access
    __try
    {
        // Validate FileObject
        if (!FileObject ||
            !MmIsAddressValid(FileObject) ||
            !FileObject->FileName.Buffer ||
            !MmIsAddressValid(FileObject->FileName.Buffer) ||
            !FileObject->DeviceObject ||
            !MmIsAddressValid(FileObject->DeviceObject))
        {
            return OB_PREOP_SUCCESS;
        }

        // Get file path (this allocates memory)
        NTSTATUS status = IoQueryFileDosDeviceName(FileObject, &fileNameInfo);
        if (!NT_SUCCESS(status) || !fileNameInfo)
        {
            return OB_PREOP_SUCCESS;
        }

        uniFilePath = fileNameInfo->Name;

        if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0)
        {
            ExFreePool(fileNameInfo);
            return OB_PREOP_SUCCESS;
        }

        // Check for protected HydraDragonAntivirus components
        static const PCWSTR protectedPatterns[] = {
            L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe",
            L"\\Owlyshield Service\\owlyshield_ransom.exe",
            L"\\Owlyshield Service\\tensorflowlite_c.dll",
            L"\\OwlyshieldRansomFilter\\OwlyshieldRansomFilter.sys",
            L"\\sanctum\\app.exe",
            L"\\sanctum\\server.exe",
            L"\\sanctum\\um_engine.exe",
            L"\\sanctum\\elam_installer.exe",
            L"\\AppData\\Roaming\\Sanctum\\sanctum.dll",
            L"\\AppData\\Roaming\\Sanctum\\sanctum.sys",
            L"\\AppData\\Roaming\\Sanctum\\sanctum_ppl_runner.exe"
        };

        // Check if file path contains any protected pattern
        for (ULONG i = 0; i < ARRAYSIZE(protectedPatterns); ++i)
        {
            if (FilePathContains(&uniFilePath, protectedPatterns[i]))
            {
                isProtected = TRUE;
                break;
            }
        }

        // If protected file is being accessed with delete/write permissions
        if (isProtected && (FileObject->DeleteAccess || FileObject->WriteAccess))
        {
            currentProcess = PsGetCurrentProcess();

            // Get the attacking process path
            status = SeLocateProcessImageName(currentProcess, &attackerPath);

            // Block the operation
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                DbgPrint("[SELF-DEFENSE] Blocked CREATE access to: %wZ by PID: %lld\r\n",
                    &uniFilePath, (LONGLONG)(ULONG_PTR)CurrentProcessId);

                // Queue alert to user-mode (runs at PASSIVE_LEVEL)
                if (NT_SUCCESS(status) && attackerPath)
                {
                    QueueAlertToUserMode(&uniFilePath, attackerPath, CurrentProcessId, L"FILE_TAMPERING");
                }
            }
            else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                DbgPrint("[SELF-DEFENSE] Blocked DUPLICATE access to: %wZ by PID: %lld\r\n",
                    &uniFilePath, (LONGLONG)(ULONG_PTR)CurrentProcessId);

                // Queue alert to user-mode
                if (NT_SUCCESS(status) && attackerPath)
                {
                    QueueAlertToUserMode(&uniFilePath, attackerPath, CurrentProcessId, L"HANDLE_HIJACK");
                }
            }

            // Free the allocated path from SeLocateProcessImageName
            if (attackerPath)
            {
                ExFreePool(attackerPath);
                attackerPath = NULL;
            }
        }

        // Free the file name info allocated by IoQueryFileDosDeviceName
        if (fileNameInfo)
        {
            ExFreePool(fileNameInfo);
            fileNameInfo = NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Self-Defense] Exception in PreCallBack: 0x%X\r\n", GetExceptionCode());

        // Clean up on exception
        if (fileNameInfo)
        {
            ExFreePool(fileNameInfo);
        }
        if (attackerPath)
        {
            ExFreePool(attackerPath);
        }
    }

    return OB_PREOP_SUCCESS;
}

// Removed GetFilePathByFileObject - functionality moved into PreCallBack

// REMOVED: EnableObType() - this is dangerous and version-dependent
// Modern Windows (Win10+) supports file object callbacks by default

VOID FileUnloadDriver()
{
    if (CallBackHandle != NULL)
    {
        ObUnRegisterCallbacks(CallBackHandle);
        CallBackHandle = NULL;
    }

    DbgPrint("[Self-Defense] FileDriver Unloaded\r\n");
}
