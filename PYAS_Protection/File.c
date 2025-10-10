#include "Drvier_File.h"

PVOID CallBackHandle = NULL;

NTSTATUS FileDriverEntry()
{
    ProtectFileByObRegisterCallbacks();
    return STATUS_SUCCESS;
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

// Helper function for case-insensitive substring search
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
        L"\\HydraDragonAntivirus\\HydraDragonAntivirusService.exe",

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
            // Block handle creation
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
                DbgPrint("[PROTECTED] Blocked CREATE access to: %wZ (PID: %ld)\r\n",
                    &uniFilePath, (ULONG64)CurrentProcessId);
            }

            // Block handle duplication
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
                DbgPrint("[PROTECTED] Blocked DUPLICATE access to: %wZ (PID: %ld)\r\n",
                    &uniFilePath, (ULONG64)CurrentProcessId);
            }
        }
    }

    // Log file access (optional - can be removed for performance)
    RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName);
    DbgPrint("PID: %ld File: %wZ%wZ %s\r\n",
        (ULONG64)CurrentProcessId,
        &uniDosName,
        &uniFilePath,
        isProtected ? "[PROTECTED]" : "");

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
    DbgPrint("FileDriver Unloaded\r\n");
}