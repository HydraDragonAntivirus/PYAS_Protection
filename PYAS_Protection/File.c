// File.c - Self-Defense Protection with User-Mode Alerting (FIXED)
#include "Driver_File.h"    // your fixed header

PVOID CallBackHandle = NULL;

// Pipe name for self-defense alerts
#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Pool tag used for allocations in this file
#define ALERT_POOL_TAG 'tlrA'  // 'Arlt' reversed as a DWORD constant

// Work item structure for deferred pipe communication
typedef struct _ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING ProtectedFile;
    UNICODE_STRING AttackingProcessPath;
    HANDLE AttackingPid;
    WCHAR AttackType[64];
} ALERT_WORK_ITEM, * PALERT_WORK_ITEM;

// Forward prototypes (if not in header)
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
);

// DriverEntry-like initializer (keeps name from your code)
NTSTATUS FileDriverEntry()
{
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
    if (!workItem)
        return;

    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    WCHAR messageBuffer[2048];
    LARGE_INTEGER timeout;

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Relative timeout: 100ms (negative = relative, 100,000 * 10ns units)
    timeout.QuadPart = -1000000; // 100ms

    // Try to open the pipe for writing (non-blocking open)
    status = ZwCreateFile(
        &pipeHandle,
        SYNCHRONIZE | FILE_WRITE_DATA,
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
        // pipe not available; just cleanup and exit
        goto Cleanup;
    }

    // Build JSON-like message for user-mode safely.
    // Use %ws for wide strings and include terminating NUL when calculating bytes.
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));

    PCWSTR protectedName = (workItem->ProtectedFile.Buffer && workItem->ProtectedFile.Length > 0) ?
        workItem->ProtectedFile.Buffer : L"Unknown";

    PCWSTR attackerPath = (workItem->AttackingProcessPath.Buffer && workItem->AttackingProcessPath.Length > 0) ?
        workItem->AttackingProcessPath.Buffer : L"Unknown";

    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%lld,\"attack_type\":\"%ws\"}",
        protectedName,
        attackerPath,
        (LONGLONG)(ULONG_PTR)workItem->AttackingPid,
        workItem->AttackType
    );

    if (!NT_SUCCESS(status))
    {
        // formatting failed
        goto Cleanup;
    }

    // Include terminating NUL in bytes to make user-mode parsing easier (optional)
    SIZE_T messageLength = (wcslen(messageBuffer) + 1) * sizeof(WCHAR);

    // Write to pipe (synchronous)
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

    if (NT_SUCCESS(status))
    {
        DbgPrint("[Self-Defense] Alert sent to user-mode: %ws attacked by PID %lld\r\n",
            protectedName, (LONGLONG)(ULONG_PTR)workItem->AttackingPid);
    }

Cleanup:
    if (pipeHandle)
    {
        ZwClose(pipeHandle);
        pipeHandle = NULL;
    }

    // Free allocated strings and workItem using same tag used for allocation
    if (workItem->ProtectedFile.Buffer)
    {
        ExFreePoolWithTag(workItem->ProtectedFile.Buffer, ALERT_POOL_TAG);
        workItem->ProtectedFile.Buffer = NULL;
    }
    if (workItem->AttackingProcessPath.Buffer)
    {
        ExFreePoolWithTag(workItem->AttackingProcessPath.Buffer, ALERT_POOL_TAG);
        workItem->AttackingProcessPath.Buffer = NULL;
    }

    ExFreePoolWithTag(workItem, ALERT_POOL_TAG);
}

// Queue a work item to notify user-mode (safe copies)
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
)
{
    PALERT_WORK_ITEM workItem;
    NTSTATUS status = STATUS_SUCCESS;

    workItem = (PALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(ALERT_WORK_ITEM),
        ALERT_POOL_TAG
    );

    if (!workItem)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(workItem, sizeof(ALERT_WORK_ITEM));

    // Copy protected file path (safe allocation, include space for NUL)
    if (ProtectedFile && ProtectedFile->Buffer && ProtectedFile->Length > 0)
    {
        workItem->ProtectedFile.Length = ProtectedFile->Length;
        workItem->ProtectedFile.MaximumLength = ProtectedFile->Length + sizeof(WCHAR);
        workItem->ProtectedFile.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool,
            workItem->ProtectedFile.MaximumLength,
            ALERT_POOL_TAG
        );

        if (workItem->ProtectedFile.Buffer)
        {
            RtlCopyMemory(workItem->ProtectedFile.Buffer, ProtectedFile->Buffer, ProtectedFile->Length);
            workItem->ProtectedFile.Buffer[ProtectedFile->Length / sizeof(WCHAR)] = L'\0';
            // set UNICODE_STRING lengths correctly
            workItem->ProtectedFile.Length = ProtectedFile->Length;
        }
        else
        {
            // failed allocation: clean up and return error
            ExFreePoolWithTag(workItem, ALERT_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
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
            ALERT_POOL_TAG
        );

        if (workItem->AttackingProcessPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackingProcessPath.Buffer, AttackingProcessPath->Buffer, AttackingProcessPath->Length);
            workItem->AttackingProcessPath.Buffer[AttackingProcessPath->Length / sizeof(WCHAR)] = L'\0';
            workItem->AttackingProcessPath.Length = AttackingProcessPath->Length;
        }
        else
        {
            // cleanup
            if (workItem->ProtectedFile.Buffer)
                ExFreePoolWithTag(workItem->ProtectedFile.Buffer, ALERT_POOL_TAG);
            ExFreePoolWithTag(workItem, ALERT_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    // Copy PID and attack type
    workItem->AttackingPid = AttackingPid;
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType ? AttackType : L"UNKNOWN");

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

    RtlZeroMemory(&CallBackReg, sizeof(CallBackReg));
    RtlZeroMemory(&OperationReg, sizeof(OperationReg));

    CallBackReg.Version = ObGetFilterVersion();
    CallBackReg.OperationRegistrationCount = 1;
    CallBackReg.RegistrationContext = NULL;

    // Altitude must be a UNICODE_STRING. Pick a sensible altitude higher than other drivers you expect.
    RtlInitUnicodeString(&CallBackReg.Altitude, L"321000"); // tune as needed

    OperationReg.ObjectType = IoFileObjectType;
    OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)PreCallBack;
    OperationReg.PostOperation = NULL;

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

// Simple substring search helper: keep this minimal to avoid risky APIs
BOOLEAN FilePathContains(PUNICODE_STRING FilePath, PCWSTR Pattern)
{
    if (!FilePath || !FilePath->Buffer || !Pattern)
        return FALSE;

    // Use wcsstr on the buffer (FilePath is a wide string, not necessarily NUL-terminated in all contexts,
    // but IoQueryFileDosDeviceName returns a UNICODE_STRING with a NUL terminator in practice).
    // We validated Length > 0 where applicable before calling this.
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

    // Ensure this callback is about file objects
    if (OperationInformation->ObjectType != *IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }

    __try
    {
        if (!FileObject ||
            !MmIsAddressValid(FileObject) ||
            !FileObject->FileName.Buffer ||
            !MmIsAddressValid(FileObject->FileName.Buffer) ||
            !FileObject->DeviceObject ||
            !MmIsAddressValid(FileObject->DeviceObject))
        {
            return OB_PREOP_SUCCESS;
        }

        // Query DOS path (allocates memory). If it fails, just exit cleanly.
        NTSTATUS status = IoQueryFileDosDeviceName(FileObject, &fileNameInfo);
        if (!NT_SUCCESS(status) || !fileNameInfo)
        {
            return OB_PREOP_SUCCESS;
        }

        uniFilePath = fileNameInfo->Name;
        if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0)
        {
            ExFreePoolWithTag(fileNameInfo, ALERT_POOL_TAG);
            return OB_PREOP_SUCCESS;
        }

        // Check for protected HydraDragonAntivirus components
        static const PCWSTR protectedPatterns[] = {
            L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe",
            L"HydraDragonAntivirus\\hydradragon\\Owlyshield\\Owlyshield Service\\owlyshield_ransom.exe",
            L"HydraDragonAntivirus\\hydradragon\\Owlyshield\\\\Owlyshield Service\\tensorflowlite_c.dll",
            L"HydraDragonAntivirus\\hydradragon\\Owlyshield\\\\OwlyshieldRansomFilter\\OwlyshieldRansomFilter.sys",
            L"\\sanctum\\app.exe",
            L"\\sanctum\\server.exe",
            L"\\sanctum\\um_engine.exe",
            L"\\sanctum\\elam_installer.exe",
            L"\\AppData\\Roaming\\Sanctum\\sanctum.dll",
            L"\\AppData\\Roaming\\Sanctum\\sanctum.sys",
            L"\\AppData\\Roaming\\Sanctum\\sanctum_ppl_runner.exe"
        };

        for (ULONG i = 0; i < ARRAYSIZE(protectedPatterns); ++i)
        {
            if (FilePathContains(&uniFilePath, protectedPatterns[i]))
            {
                isProtected = TRUE;
                break;
            }
        }

        // If protected file is being opened with delete or write access on this new handle
        if (isProtected && (FileObject->DeleteAccess || FileObject->WriteAccess))
        {
            currentProcess = PsGetCurrentProcess();

            // Locate process image name (allocates memory that must be freed by caller)
            status = SeLocateProcessImageName(currentProcess, &attackerPath);

            // For create/duplicate operations we can strip requested access rights on this incoming handle.
            // NOTE: this prevents *new* handles from getting delete/write access, but it does NOT revoke
            // access from already-open handles. For robust prevention of deletion, use a mini-filter to intercept
            // file disposition IRPs (see comments below).
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                // Strip requested access for the newly-created handle
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                DbgPrint("[SELF-DEFENSE] Stripped CREATE access to: %wZ by PID: %lld\r\n",
                    &uniFilePath, (LONGLONG)(ULONG_PTR)CurrentProcessId);

                if (NT_SUCCESS(status) && attackerPath)
                {
                    QueueAlertToUserMode(&uniFilePath, attackerPath, CurrentProcessId, L"FILE_TAMPERING");
                }
            }
            else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                DbgPrint("[SELF-DEFENSE] Stripped DUPLICATE access to: %wZ by PID: %lld\r\n",
                    &uniFilePath, (LONGLONG)(ULONG_PTR)CurrentProcessId);

                if (NT_SUCCESS(status) && attackerPath)
                {
                    QueueAlertToUserMode(&uniFilePath, attackerPath, CurrentProcessId, L"HANDLE_HIJACK");
                }
            }

            // Free attackerPath from SeLocateProcessImageName
            if (attackerPath)
            {
                ExFreePoolWithTag(attackerPath, ALERT_POOL_TAG);
                attackerPath = NULL;
            }
        }

        // Free fileNameInfo allocated by IoQueryFileDosDeviceName
        if (fileNameInfo)
        {
            ExFreePoolWithTag(fileNameInfo, ALERT_POOL_TAG);
            fileNameInfo = NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Self-Defense] Exception in PreCallBack: 0x%X\r\n", GetExceptionCode());

        if (fileNameInfo)
        {
            ExFreePoolWithTag(fileNameInfo, ALERT_POOL_TAG);
            fileNameInfo = NULL;
        }
        if (attackerPath)
        {
            ExFreePoolWithTag(attackerPath, ALERT_POOL_TAG);
            attackerPath = NULL;
        }
    }

    // Per MSDN, pre-op callback should return OB_PREOP_SUCCESS (we altered DesiredAccess above)
    return OB_PREOP_SUCCESS;
}

// Unregister callbacks and cleanup
VOID FileUnloadDriver()
{
    if (CallBackHandle != NULL)
    {
        ObUnRegisterCallbacks(CallBackHandle);  // use correct API to unregister
        CallBackHandle = NULL;
    }

    DbgPrint("[Self-Defense] FileDriver Unloaded\r\n");
}
