#include "Driver_File.h"

// Global handle for the registered callback
PVOID CallBackHandle = NULL;

// Named pipe for sending alerts to a user-mode application
#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Pool tag for memory allocations, useful for debugging memory leaks. 'Arlt'
#define ALERT_POOL_TAG 'tlrA'

// Structure to hold data for the worker thread that sends alerts.
// This is used to pass information from the high-IRQL callback to a passive-level worker.
typedef struct _ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING ProtectedFile;
    UNICODE_STRING AttackingProcessPath;
    HANDLE AttackingPid;
    WCHAR AttackType[64];
} ALERT_WORK_ITEM, * PALERT_WORK_ITEM;


// Forward declaration for the alert queuing function
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
);

/**
 * @brief Main entry point for this driver component.
 *
 * This function initializes the file protection by registering object manager callbacks.
 *
 * @return NTSTATUS - STATUS_SUCCESS on success, or an error code on failure.
 */
NTSTATUS FileDriverEntry()
{
    NTSTATUS status = ProtectFileByObRegisterCallbacks();
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Self-Defense] File protection callbacks initialized successfully.\r\n");
    }
    else
    {
        DbgPrint("[Self-Defense] FAILED to initialize file protection callbacks: 0x%X\r\n", status);
    }
    return status;
}

/**
 * @brief Worker routine that sends an alert to user-mode via a named pipe.
 *
 * This function runs at PASSIVE_LEVEL, allowing it to perform blocking operations
 * like writing to a file (the named pipe).
 *
 * @param Context A pointer to the ALERT_WORK_ITEM containing the alert details.
 */
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
    WCHAR messageBuffer[2048]; // A large buffer for the JSON message

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);
    InitializeObjectAttributes(&objAttr, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // Try to open the named pipe. If the user-mode listener isn't running, this will fail.
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

    if (NT_SUCCESS(status))
    {
        // Safely format the alert message into a JSON-like string.
        RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
        PCWSTR protectedName = (workItem->ProtectedFile.Buffer) ? workItem->ProtectedFile.Buffer : L"Unknown";
        PCWSTR attackerPath = (workItem->AttackingProcessPath.Buffer) ? workItem->AttackingProcessPath.Buffer : L"Unknown";

        RtlStringCbPrintfW(
            messageBuffer,
            sizeof(messageBuffer),
            L"{\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%lld,\"attack_type\":\"%ws\"}",
            protectedName,
            attackerPath,
            (LONGLONG)(ULONG_PTR)workItem->AttackingPid,
            workItem->AttackType
        );

        // Calculate length and write the message to the pipe.
        SIZE_T messageLength = (wcslen(messageBuffer) + 1) * sizeof(WCHAR);
        ZwWriteFile(pipeHandle, NULL, NULL, NULL, &ioStatusBlock, messageBuffer, (ULONG)messageLength, NULL, NULL);

        DbgPrint("[Self-Defense] Alert sent to user-mode: %ws attacked by PID %lld\r\n",
            protectedName, (LONGLONG)(ULONG_PTR)workItem->AttackingPid);
    }

    // Cleanup: Close the pipe handle and free all memory associated with the work item.
    if (pipeHandle)
    {
        ZwClose(pipeHandle);
    }

    if (workItem->ProtectedFile.Buffer)
    {
        ExFreePoolWithTag(workItem->ProtectedFile.Buffer, ALERT_POOL_TAG);
    }
    if (workItem->AttackingProcessPath.Buffer)
    {
        ExFreePoolWithTag(workItem->AttackingProcessPath.Buffer, ALERT_POOL_TAG);
    }
    ExFreePoolWithTag(workItem, ALERT_POOL_TAG);
}

/**
 * @brief Allocates and queues a work item to send an alert from a passive-level thread.
 *
 * This function safely copies all necessary data into a new allocation to be handled
 * by the SendAlertWorker routine. This is necessary because the source data may be
 * transient.
 *
 * @param ProtectedFile The path of the file being protected.
 * @param AttackingProcessPath The path of the process attempting the access.
 * @param AttackingPid The Process ID of the attacker.
 * @param AttackType A string describing the type of attack (e.g., "FILE_TAMPERING").
 *
 * @return NTSTATUS - STATUS_SUCCESS on success, or STATUS_INSUFFICIENT_RESOURCES on allocation failure.
 */
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
)
{
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(ALERT_WORK_ITEM), ALERT_POOL_TAG);

    if (!workItem)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(workItem, sizeof(ALERT_WORK_ITEM));

    // Safely copy strings into the work item structure
    if (ProtectedFile && ProtectedFile->Buffer && ProtectedFile->Length > 0)
    {
        workItem->ProtectedFile.MaximumLength = ProtectedFile->Length + sizeof(WCHAR);
        workItem->ProtectedFile.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool, workItem->ProtectedFile.MaximumLength, ALERT_POOL_TAG);

        if (workItem->ProtectedFile.Buffer)
        {
            RtlCopyMemory(workItem->ProtectedFile.Buffer, ProtectedFile->Buffer, ProtectedFile->Length);
            workItem->ProtectedFile.Buffer[ProtectedFile->Length / sizeof(WCHAR)] = L'\0'; // Null-terminate
            workItem->ProtectedFile.Length = ProtectedFile->Length;
        }
    }

    if (AttackingProcessPath && AttackingProcessPath->Buffer && AttackingProcessPath->Length > 0)
    {
        workItem->AttackingProcessPath.MaximumLength = AttackingProcessPath->Length + sizeof(WCHAR);
        workItem->AttackingProcessPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(
            NonPagedPool, workItem->AttackingProcessPath.MaximumLength, ALERT_POOL_TAG);

        if (workItem->AttackingProcessPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackingProcessPath.Buffer, AttackingProcessPath->Buffer, AttackingProcessPath->Length);
            workItem->AttackingProcessPath.Buffer[AttackingProcessPath->Length / sizeof(WCHAR)] = L'\0'; // Null-terminate
            workItem->AttackingProcessPath.Length = AttackingProcessPath->Length;
        }
    }

    workItem->AttackingPid = AttackingPid;
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType ? AttackType : L"UNKNOWN");

    // Initialize and queue the work item to be executed by a system worker thread.
    ExInitializeWorkItem(&workItem->WorkItem, SendAlertWorker, workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}


/**
 * @brief Registers the object manager callbacks for file objects.
 *
 * This sets up the driver to receive notifications for handle creation and duplication
 * operations on files.
 *
 * @return NTSTATUS - Status of the ObRegisterCallbacks call.
 */
NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION callBackReg;
    OB_OPERATION_REGISTRATION operationReg;
    NTSTATUS status;

    RtlZeroMemory(&callBackReg, sizeof(callBackReg));
    RtlZeroMemory(&operationReg, sizeof(operationReg));

    callBackReg.Version = ObGetFilterVersion();
    callBackReg.OperationRegistrationCount = 1;
    callBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&callBackReg.Altitude, L"321000"); // Example altitude

    operationReg.ObjectType = IoFileObjectType;
    operationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)PreCallBack;
    operationReg.PostOperation = NULL;

    callBackReg.OperationRegistration = &operationReg;

    status = ObRegisterCallbacks(&callBackReg, &CallBackHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Self-Defense] ObRegisterCallbacks failed: 0x%X\r\n", status);
    }

    return status;
}

/**
 * @brief A simple helper to check if a wide string contains a substring.
 *
 * @param FilePath The UNICODE_STRING to search within.
 * @param Pattern The wide string pattern to search for.
 * @return BOOLEAN - TRUE if the pattern is found, FALSE otherwise.
 */
BOOLEAN FilePathContains(PUNICODE_STRING FilePath, PCWSTR Pattern)
{
    if (!FilePath || !FilePath->Buffer || !Pattern)
        return FALSE;
    // wcsstr is safe to use here as IoQueryFileDosDeviceName returns a null-terminated string.
    return (wcsstr(FilePath->Buffer, Pattern) != NULL);
}

/**
 * @brief The pre-operation callback routine.
 *
 * This function is called by the system before a handle is created or duplicated for a file.
 * It checks if the target file is protected and if the operation is malicious (e.g., requests write or delete access).
 *
 * @param RegistrationContext The context provided during registration (NULL in this case).
 * @param OperationInformation Contains details about the operation being performed.
 *
 * @return OB_PREOP_CALLBACK_STATUS - Always returns OB_PREOP_SUCCESS. Access rights are stripped internally if needed.
 */
OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    PFILE_OBJECT fileObject = (PFILE_OBJECT)OperationInformation->Object;
    HANDLE currentProcessId = PsGetCurrentProcessId();
    BOOLEAN isProtected = FALSE;
    POBJECT_NAME_INFORMATION fileNameInfo = NULL;
    PUNICODE_STRING attackerPath = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistrationContext);

    // We only care about file objects.
    if (OperationInformation->ObjectType != *IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }

    // Use a structured exception handler for safety when accessing kernel pointers.
    __try
    {
        // Basic validation of the file object pointer
        if (!fileObject || !MmIsAddressValid(fileObject) || !fileObject->FileName.Buffer)
        {
            return OB_PREOP_SUCCESS;
        }

        // IoQueryFileDosDeviceName allocates memory which we must free.
        status = IoQueryFileDosDeviceName(fileObject, &fileNameInfo);
        if (!NT_SUCCESS(status) || !fileNameInfo || !fileNameInfo->Name.Buffer || fileNameInfo->Name.Length == 0)
        {
            // If we can't get the name, we can't check it.
            leave;
        }

        // Define the list of protected file/path patterns.
        static const PCWSTR protectedPatterns[] = {
            L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe",
            L"HydraDragonAntivirus\\hydradragon\\Owlyshield\\Owlyshield Service\\owlyshield_ransom.exe",
            L"HydraDragonAntivirus\\hydradragon\\Owlyshield\\Owlyshield Service\\tensorflowlite_c.dll",
            L"HydraDragonAntivirus\\hydradragon\\Owlyshield\\OwlyshieldRansomFilter\\OwlyshieldRansomFilter.sys",
            L"\\sanctum\\app.exe",
            L"\\sanctum\\server.exe",
            L"\\sanctum\\um_engine.exe",
            L"\\sanctum\\elam_installer.exe",
            L"\\AppData\\Roaming\\Sanctum\\sanctum.dll",
            L"\\AppData\\Roaming\\Sanctum\\sanctum.sys",
            L"\\AppData\\Roaming\\Sanctum\\sanctum_ppl_runner.exe"
        };

        // Check if the file path matches any of the protected patterns.
        for (ULONG i = 0; i < ARRAYSIZE(protectedPatterns); ++i)
        {
            if (FilePathContains(&fileNameInfo->Name, protectedPatterns[i]))
            {
                isProtected = TRUE;
                break;
            }
        }

        // If the file is protected and the operation requests write or delete access...
        if (isProtected && (OperationInformation->Parameters->CreateHandleInformation.DesiredAccess & (DELETE | FILE_WRITE_DATA)))
        {
            // SeLocateProcessImageName allocates memory which we must free.
            status = SeLocateProcessImageName(PsGetCurrentProcess(), &attackerPath);

            // Block the operation by stripping the requested access rights.
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                DbgPrint("[Self-Defense] Stripped CREATE access to: %wZ by PID: %lld\r\n",
                    &fileNameInfo->Name, (LONGLONG)(ULONG_PTR)currentProcessId);

                QueueAlertToUserMode(&fileNameInfo->Name, attackerPath, currentProcessId, L"FILE_TAMPERING_BLOCKED");
            }
            else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                DbgPrint("[Self-Defense] Stripped DUPLICATE access to: %wZ by PID: %lld\r\n",
                    &fileNameInfo->Name, (LONGLONG)(ULONG_PTR)currentProcessId);

                QueueAlertToUserMode(&fileNameInfo->Name, attackerPath, currentProcessId, L"HANDLE_HIJACK_BLOCKED");
            }
        }
    }
    __finally
    {
        // CRITICAL: Free any memory that was allocated, regardless of what happened.
        if (fileNameInfo)
        {
            ExFreePool(fileNameInfo);
        }
        if (attackerPath)
        {
            // SeLocateProcessImageName uses general paged pool, no tag needed.
            ExFreePool(attackerPath);
        }
    }

    return OB_PREOP_SUCCESS;
}

/**
 * @brief The driver unload routine.
 *
 * This function is responsible for cleaning up all resources, primarily unregistering
 * the object manager callbacks to allow the driver to be unloaded safely.
 */
VOID FileUnloadDriver()
{
    if (CallBackHandle != NULL)
    {
        ObUnRegisterCallbacks(CallBackHandle);
        CallBackHandle = NULL;
    }
    DbgPrint("[Self-Defense] File protection driver unloaded.\r\n");
}
