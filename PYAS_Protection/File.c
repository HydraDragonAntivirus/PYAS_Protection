#include "Driver_File.h"

//================================================================================
// Global Variables & Defines
//================================================================================

// Global handle for the registered callback.
PVOID CallBackHandle = NULL;

// Named pipe for sending alerts to a user-mode application.
#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

// Pool tag for memory allocations, useful for debugging memory leaks.
#define ALERT_POOL_TAG 'tlrA'

//================================================================================
// Structures
//================================================================================

// Structure to hold data for the worker thread that sends alerts.
// This is used to pass information from the high-IRQL callback to a passive-level worker.
typedef struct _ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING ProtectedFile;
    UNICODE_STRING AttackingProcessPath;
    HANDLE AttackingPid;
    WCHAR AttackType[64];
} ALERT_WORK_ITEM, * PALERT_WORK_ITEM;

//================================================================================
// Forward Declarations
//================================================================================

// Worker routine that sends alert data to user-mode.
VOID SendAlertWorker(PVOID Context);

// Function to queue the alert work item.
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
);

// The core pre-operation callback routine.
OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

//================================================================================
// Driver Entry & Unload
//================================================================================

/**
 * @brief Main entry point for this driver component.
 *
 * This function initializes the file protection by registering object manager callbacks.
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
 * @brief The driver unload routine.
 *
 * Unregisters the object manager callbacks to allow the driver to be unloaded safely.
 */
VOID FileUnloadDriver()
{
    if (CallBackHandle != NULL)
    {
        ObUnRegisterCallbacks(CallBackHandle);
        CallBackHandle = NULL;
        DbgPrint("[Self-Defense] File protection callbacks unregistered.\r\n");
    }
    DbgPrint("[Self-Defense] Driver unloaded.\r\n");
}

//================================================================================
// Core Logic: Callback Registration & Handling
//================================================================================

/**
 * @brief Manually enables callbacks on an object type.
 *
 * This is an undocumented technique to set the 'SupportsObjectCallbacks' flag
 * on an object type structure, which is necessary for file objects on some
 * Windows versions.
 */
VOID EnableObType(POBJECT_TYPE ObjectType)
{
    POBJECT_TYPE_TEMP ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
    ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
}


/**
 * @brief Registers the object manager callbacks for file objects.
 *
 * Sets up the driver to receive notifications for handle creation/duplication on files.
 */
NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION callBackReg;
    OB_OPERATION_REGISTRATION operationReg;
    NTSTATUS status;

    // Manually enable callbacks for the File Object type. This is crucial.
    EnableObType(*IoFileObjectType);

    RtlZeroMemory(&callBackReg, sizeof(callBackReg));
    RtlZeroMemory(&operationReg, sizeof(operationReg));

    callBackReg.Version = ObGetFilterVersion();
    callBackReg.OperationRegistrationCount = 1;
    callBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&callBackReg.Altitude, L"321000"); // Altitude for filtering order.

    operationReg.ObjectType = IoFileObjectType;
    operationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)PreCallBack;
    operationReg.PostOperation = NULL; // No post-op needed.

    callBackReg.OperationRegistration = &operationReg;

    status = ObRegisterCallbacks(&callBackReg, &CallBackHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Self-Defense] ObRegisterCallbacks failed: 0x%X\r\n", status);
    }

    return status;
}

/**
 * @brief The pre-operation callback routine.
 *
 * This function is called by the system before a handle is created or duplicated for a file.
 * It checks if the target file is protected and if the operation requests malicious access.
 */
OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    // We only care about file objects, not other object types.
    if (OperationInformation->ObjectType != *IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }

    // Only kernel-mode operations can be trusted.
    if (OperationInformation->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    POBJECT_NAME_INFORMATION fileNameInfo = NULL;
    PUNICODE_STRING attackerPath = NULL;
    NTSTATUS status;
    BOOLEAN isProtected = FALSE;

    // Use a structured exception handler for safety when accessing potentially invalid user-mode pointers.
    __try
    {
        // Get the full path of the file being accessed.
        // IoQueryFileDosDeviceName allocates memory which we must free.
        status = IoQueryFileDosDeviceName((PFILE_OBJECT)OperationInformation->Object, &fileNameInfo);
        if (!NT_SUCCESS(status) || !fileNameInfo || !fileNameInfo->Name.Buffer || fileNameInfo->Name.Length == 0)
        {
            // If we can't get the name, we can't protect it.
            leave;
        }

        // --- UNIFIED LIST OF PROTECTED FILES ---
        static const PCWSTR protectedPatterns[] = {
            // Specific file paths
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

        // Check if the file path contains any of the protected patterns.
        for (ULONG i = 0; i < ARRAYSIZE(protectedPatterns); ++i)
        {
            if (wcsstr(fileNameInfo->Name.Buffer, protectedPatterns[i]) != NULL)
            {
                isProtected = TRUE;
                break;
            }
        }

        // If the file is protected, check the requested access rights.
        ACCESS_MASK desiredAccess = 0;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        }
        else // OB_OPERATION_HANDLE_DUPLICATE
        {
            desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        // We want to block any attempt to write to or delete the file.
        if (isProtected && (desiredAccess & (DELETE | FILE_WRITE_DATA | GENERIC_WRITE)))
        {
            HANDLE currentProcessId = PsGetCurrentProcessId();

            // Get the image path of the process making the request.
            status = SeLocateProcessImageName(PsGetCurrentProcess(), &attackerPath);

            // --- BLOCK THE OPERATION ---
            // We block by stripping the dangerous access rights from the request.
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(DELETE | FILE_WRITE_DATA | GENERIC_WRITE);
                DbgPrint("[Self-Defense] Stripped CREATE access to: %wZ by PID: %p\r\n", &fileNameInfo->Name, currentProcessId);
                QueueAlertToUserMode(&fileNameInfo->Name, attackerPath, currentProcessId, L"FILE_TAMPERING_BLOCKED");
            }
            else // OB_OPERATION_HANDLE_DUPLICATE
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(DELETE | FILE_WRITE_DATA | GENERIC_WRITE);
                DbgPrint("[Self-Defense] Stripped DUPLICATE access to: %wZ by PID: %p\r\n", &fileNameInfo->Name, currentProcessId);
                QueueAlertToUserMode(&fileNameInfo->Name, attackerPath, currentProcessId, L"HANDLE_HIJACK_BLOCKED");
            }
        }
    }
    __finally
    {
        // CRITICAL: Free any memory that was allocated in the __try block.
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

//================================================================================
// User-Mode Alerting via Named Pipe
//================================================================================

/**
 * @brief Allocates and queues a work item to send an alert from a passive-level thread.
 *
 * This function safely copies all necessary data into a new allocation to be handled
 * by the SendAlertWorker routine. This is necessary because the source data may be
 * transient and we cannot block at the high IRQL of the callback.
 */
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
)
{
    // Allocate memory for the work item from non-paged pool.
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(ALERT_WORK_ITEM), ALERT_POOL_TAG);

    if (!workItem)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workItem, sizeof(ALERT_WORK_ITEM));

    // Safely copy the protected file path into the work item structure.
    if (ProtectedFile && ProtectedFile->Buffer && ProtectedFile->Length > 0)
    {
        workItem->ProtectedFile.MaximumLength = ProtectedFile->Length + sizeof(WCHAR);
        workItem->ProtectedFile.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, workItem->ProtectedFile.MaximumLength, ALERT_POOL_TAG);
        if (workItem->ProtectedFile.Buffer)
        {
            RtlCopyUnicodeString(&workItem->ProtectedFile, ProtectedFile);
        }
    }

    // Safely copy the attacker's process path.
    if (AttackingProcessPath && AttackingProcessPath->Buffer && AttackingProcessPath->Length > 0)
    {
        workItem->AttackingProcessPath.MaximumLength = AttackingProcessPath->Length + sizeof(WCHAR);
        workItem->AttackingProcessPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, workItem->AttackingProcessPath.MaximumLength, ALERT_POOL_TAG);
        if (workItem->AttackingProcessPath.Buffer)
        {
            RtlCopyUnicodeString(&workItem->AttackingProcessPath, AttackingProcessPath);
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
 * @brief Worker routine that sends an alert to user-mode via a named pipe.
 *
 * This function runs at PASSIVE_LEVEL, allowing it to perform blocking operations.
 */
VOID SendAlertWorker(PVOID Context)
{
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)Context;
    if (!workItem) return;

    NTSTATUS status;
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    // A large buffer for the JSON-like message.
    WCHAR messageBuffer[1024];

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);
    InitializeObjectAttributes(&objAttr, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // Try to open the named pipe. This will only succeed if a user-mode application is listening.
    status = ZwCreateFile(&pipeHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (NT_SUCCESS(status))
    {
        PCWSTR protectedName = (workItem->ProtectedFile.Buffer) ? workItem->ProtectedFile.Buffer : L"Unknown";
        PCWSTR attackerPath = (workItem->AttackingProcessPath.Buffer) ? workItem->AttackingProcessPath.Buffer : L"Unknown";

        // Safely format the alert message into a string.
        RtlStringCbPrintfW(messageBuffer, sizeof(messageBuffer),
            L"{\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%p,\"attack_type\":\"%ws\"}",
            protectedName, attackerPath, workItem->AttackingPid, workItem->AttackType);

        SIZE_T messageLength = (wcslen(messageBuffer) + 1) * sizeof(WCHAR);
        ZwWriteFile(pipeHandle, NULL, NULL, NULL, &ioStatusBlock, messageBuffer, (ULONG)messageLength, NULL, NULL);
        ZwClose(pipeHandle);
    }

    // --- CLEANUP ---
    // Free all memory that was allocated for the work item.
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
