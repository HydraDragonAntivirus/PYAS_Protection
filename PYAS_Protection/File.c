// File.c - Self-Defense Protection with User-Mode Alerting
#include "Drvier_File.h"
#include <ntstrsafe.h>

PVOID CallBackHandle = NULL;

// Pipe name for self-defense alerts
#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"

NTSTATUS FileDriverEntry()
{
    // Register file protection callbacks
    ProtectFileByObRegisterCallbacks();
    DbgPrint("[Self-Defense] File protection initialized\r\n");
    return STATUS_SUCCESS;
}

NTSTATUS SendAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
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

    // Initialize pipe name
    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

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
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        // Pipe not available - service may not be running yet
        return status;
    }

    // Build JSON-like message for user-mode
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));

    PCWSTR protectedName = ProtectedFile->Buffer ? ProtectedFile->Buffer : L"Unknown";
    PCWSTR attackerPath = AttackingProcessPath->Buffer ? AttackingProcessPath->Buffer : L"Unknown";

    // Use RtlStringCchPrintfW instead of RtlStringCbPrintfW
    status = RtlStringCchPrintfW(
        messageBuffer,
        sizeof(messageBuffer) / sizeof(WCHAR),
        L"{\"protected_file\":\"%s\",\"attacker_path\":\"%s\",\"attacker_pid\":%lld,\"attack_type\":\"%s\"}",
        protectedName,
        attackerPath,
        (LONGLONG)(ULONG_PTR)AttackingPid,
        AttackType
    );

    if (!NT_SUCCESS(status))
    {
        ZwClose(pipeHandle);
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
        DbgPrint("[Self-Defense] Alert sent to user-mode: %wZ attacked by PID %lld\r\n",
            ProtectedFile, (LONGLONG)(ULONG_PTR)AttackingPid);
    }

    return status;
}

NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION  CallBackReg;
    OB_OPERATION_REGISTRATION OperationReg;
    NTSTATUS Status;

    EnableObType(*IoFileObjectType);

    memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
    CallBackReg.Version = ObGetFilterVersion();
    CallBackReg.OperationRegistrationCount = 1;
    CallBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&CallBackReg.Altitude, L"321000");

    memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION));

    OperationReg.ObjectType = IoFileObjectType;
    OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCallBack;

    CallBackReg.OperationRegistration = &OperationReg;

    Status = ObRegisterCallbacks(&CallBackReg, &CallBackHandle);
    if (!NT_SUCCESS(Status))
    {
        Status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        Status = STATUS_SUCCESS;
    }
    return Status;
}

BOOLEAN FilePathContains(PUNICODE_STRING FilePath, PCWSTR Pattern)
{
    if (!FilePath || !FilePath->Buffer || !Pattern)
        return FALSE;

    return (wcsstr(FilePath->Buffer, Pattern) != NULL);
}

OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNICODE_STRING uniDosName;
    UNICODE_STRING uniFilePath;
    PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
    HANDLE CurrentProcessId = PsGetCurrentProcessId();
    BOOLEAN isProtected = FALSE;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    PUNICODE_STRING attackerPath = NULL;

    if (OperationInformation->ObjectType != *IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }

    // Filter invalid pointers
    if (FileObject->FileName.Buffer == NULL ||
        !MmIsAddressValid(FileObject->FileName.Buffer) ||
        FileObject->DeviceObject == NULL ||
        !MmIsAddressValid(FileObject->DeviceObject))
    {
        return OB_PREOP_SUCCESS;
    }

    uniFilePath = GetFilePathByFileObject(FileObject);
    if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0)
    {
        return OB_PREOP_SUCCESS;
    }

    // Check for protected HydraDragonAntivirus components
    // Only .exe, .sys, .dll files are protected
    static const PCWSTR protectedPatterns[] = {
        // HydraDragonAntivirus Service
        L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe",

        // Owlyshield Service executables and DLLs
        L"\\Owlyshield Service\\owlyshield_ransom.exe",
        L"\\Owlyshield Service\\tensorflowlite_c.dll",

        // OwlyshieldRansomFilter driver
        L"\\OwlyshieldRansomFilter\\OwlyshieldRansomFilter.sys",

        // Sanctum Desktop files (app.exe, server.exe, um_engine.exe, elam_installer.exe)
        L"\\sanctum\\app.exe",
        L"\\sanctum\\server.exe",
        L"\\sanctum\\um_engine.exe",
        L"\\sanctum\\elam_installer.exe",

        // Sanctum AppData Roaming files
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
    if (isProtected)
    {
        if (FileObject->DeleteAccess == TRUE || FileObject->WriteAccess == TRUE)
        {
            // Get the attacking process path
            NTSTATUS status = SeLocateProcessImageName(currentProcess, &attackerPath);

            // Block the operation
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                DbgPrint("[SELF-DEFENSE] Blocked CREATE access to: %wZ by PID: %ld\r\n",
                    &uniFilePath, (ULONG64)CurrentProcessId);

                // Send alert to user-mode
                if (NT_SUCCESS(status) && attackerPath)
                {
                    SendAlertToUserMode(&uniFilePath, attackerPath, CurrentProcessId, L"FILE_TAMPERING");
                }
            }

            if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                DbgPrint("[SELF-DEFENSE] Blocked DUPLICATE access to: %wZ by PID: %ld\r\n",
                    &uniFilePath, (ULONG64)CurrentProcessId);

                // Send alert to user-mode
                if (NT_SUCCESS(status) && attackerPath)
                {
                    SendAlertToUserMode(&uniFilePath, attackerPath, CurrentProcessId, L"HANDLE_HIJACK");
                }
            }

            // Free the allocated path
            if (attackerPath)
            {
                ExFreePool(attackerPath);
            }
        }
    }

    // Optional logging (can be removed for performance)
    RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName);

    return OB_PREOP_SUCCESS;
}

UNICODE_STRING GetFilePathByFileObject(PVOID FileObject)
{
    POBJECT_NAME_INFORMATION ObjetNameInfor;
    UNICODE_STRING emptyString = { 0 };

    if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjetNameInfor)))
    {
        return ObjetNameInfor->Name;
    }

    return emptyString;
}

VOID EnableObType(POBJECT_TYPE ObjectType)
{
    POBJECT_TYPE_TEMP ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
    ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
}

VOID FileUnloadDriver()
{
    if (CallBackHandle != NULL)
    {
        ObUnRegisterCallbacks(CallBackHandle);
    }

    DbgPrint("[Self-Defense] FileDriver Unloaded\r\n");
}
