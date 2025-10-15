// Process.c - Process & Thread protection with PID tracking and HydraDragon AV exemption
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver_Process.h"

//
// --- Globals ---
//

LIST_ENTRY g_ProtectedPidsList;
KSPIN_LOCK g_ProtectedPidsLock;
PVOID g_ObRegistrationHandle = NULL;

//
// --- Driver Entry and Unload ---
//

NTSTATUS ProcessDriverEntry() {
    NTSTATUS status = ProtectProcess();
    if (NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] Initialized successfully\r\n");
    }
    else {
        DbgPrint("[Process-Protection] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

NTSTATUS ProcessDriverUnload() {
    // Unregister the object callback first
    if (g_ObRegistrationHandle) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }

    // Unregister the process creation notification routine
    // The first parameter should be the same function pointer used for registration.
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);

    // Clean up the protected PID list
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);

    while (!IsListEmpty(&g_ProtectedPidsList)) {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_ProtectedPidsList);
        PPROTECTED_PID_ENTRY pPidEntry = CONTAINING_RECORD(pEntry, PROTECTED_PID_ENTRY, ListEntry);
        ExFreePoolWithTag(pPidEntry, PID_LIST_TAG);
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DbgPrint("[Process-Protection] Unloaded\r\n");
    return STATUS_SUCCESS;
}

//
// --- Initialization ---
//

NTSTATUS ProtectProcess() {
    // Initialize the PID list and spinlock
    InitializeListHead(&g_ProtectedPidsList);
    KeInitializeSpinLock(&g_ProtectedPidsLock);

    // Register for process creation/exit notifications
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] Failed to register process notify routine: 0x%X\r\n", status);
        return status;
    }

    // Register object handle callbacks for process and thread protection
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg[2];

    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 2;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");

    // Process protection
    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = preCall;
    opReg[0].PostOperation = NULL;

    // Thread protection
    opReg[1].ObjectType = PsThreadType;
    opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = threadPreCall;
    opReg[1].PostOperation = NULL;

    obReg.OperationRegistration = opReg;

    status = ObRegisterCallbacks(&obReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] ObRegisterCallbacks failed: 0x%X\r\n", status);
        // If this fails, unregister the process notify routine
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    }
    else {
        DbgPrint("[Process-Protection] ObRegisterCallbacks succeeded\r\n");
    }

    return status;
}

//
// --- Core Protection Logic ---
//

// NOTIFICATION ROUTINE: Called on every process creation and exit.
VOID CreateProcessNotifyRoutine(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    if (CreateInfo) { // Process is starting
        if (IsProtectedProcessByPath(Process)) {
            PPROTECTED_PID_ENTRY pNewEntry = ExAllocatePoolWithTag(
                NonPagedPool, sizeof(PROTECTED_PID_ENTRY), PID_LIST_TAG
            );

            if (pNewEntry) {
                pNewEntry->ProcessId = ProcessId;

                KLOCK_QUEUE_HANDLE lockHandle;
                KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);
                InsertTailList(&g_ProtectedPidsList, &pNewEntry->ListEntry);
                KeReleaseInStackQueuedSpinLock(&lockHandle);

                DbgPrint("[Process-Protection] Protected process started: PID %llu\r\n",
                    (unsigned long long)(ULONG_PTR)ProcessId);
            }
        }
    }
    else { // Process is exiting
        KLOCK_QUEUE_HANDLE lockHandle;
        KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);

        PLIST_ENTRY pCurrent = g_ProtectedPidsList.Flink;
        while (pCurrent != &g_ProtectedPidsList) {
            PPROTECTED_PID_ENTRY pEntry = CONTAINING_RECORD(pCurrent, PROTECTED_PID_ENTRY, ListEntry);
            if (pEntry->ProcessId == ProcessId) {
                RemoveEntryList(&pEntry->ListEntry);
                ExFreePoolWithTag(pEntry, PID_LIST_TAG);
                DbgPrint("[Process-Protection] Protected process terminated: PID %llu\r\n",
                    (unsigned long long)(ULONG_PTR)ProcessId);
                break;
            }
            pCurrent = pCurrent->Flink;
        }

        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }
}

// Helper: Check if process is HydraDragonAntivirus (YOUR AV ONLY)
BOOLEAN IsHydraDragonAV(PEPROCESS Process) {
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer) {
        if (pImageName) ExFreePool(pImageName);
        return FALSE;
    }

    // ONLY match your specific HydraDragonAntivirus path
    // This prevents malware from spoofing other AV paths
    static const PCWSTR hydraDragonPattern = L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe";

    if (UnicodeStringEndsWithInsensitive(pImageName, hydraDragonPattern)) {
        result = TRUE;
        DbgPrint("[Process-Protection] Detected HydraDragonAV: %wZ\r\n", pImageName);
    }

    ExFreePool(pImageName);
    return result;
}

// CALLBACK: Intercepts process handle operations
OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (pOperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS currentProc = PsGetCurrentProcess();
    HANDLE callerPid = PsGetProcessId(currentProc);
    PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProc);

    if (callerPid == targetPid) {
        return OB_PREOP_SUCCESS; // Allow self-access
    }

    BOOLEAN callerIsProtected = IsProtectedProcessByPid(callerPid);
    BOOLEAN targetIsProtected = IsProtectedProcessByPid(targetPid);

    // **GRANT FULL ACCESS TO HYDRADRAGON AV ONLY**
    if (callerIsProtected && targetIsProtected) {
        DbgPrint("[Process-Protection] Granting full access because caller is protected (AV): %llu -> %llu\r\n",
            (unsigned long long)(ULONG_PTR)callerPid, (unsigned long long)(ULONG_PTR)targetPid);

        // Grant full access
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
        }
        else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
        }

        return OB_PREOP_SUCCESS;
    }

    // Main protection: External -> Protected (strip dangerous access)
    if (!callerIsProtected && targetIsProtected) {
        ACCESS_MASK DesiredAccess = 0;
        PCWSTR AttackType = NULL;

        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            DesiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            AttackType = L"PROCESS_OPEN_BLOCKED";
        }
        else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            DesiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
            AttackType = L"PROCESS_DUPLICATE_BLOCKED";
        }

        // If the caller requests dangerous permissions, strip them instead of blocking.
        if ((DesiredAccess & PROCESS_DANGEROUS_MASK) && AttackType) {
            DbgPrint("[Process-Protection] STRIPPING DANGEROUS ACCESS from PID %llu to protected PID %llu\r\n",
                (unsigned long long)(ULONG_PTR)callerPid, (unsigned long long)(ULONG_PTR)targetPid);

            QueueProcessAlertToUserMode(targetProc, currentProc, AttackType);

            // Strip dangerous access rights
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DANGEROUS_MASK;
            }
            else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_DANGEROUS_MASK;
            }
        }
    }

    // Always return success for older WDKs; we only modify access rights.
    return OB_PREOP_SUCCESS;
}

// CALLBACK: Intercepts thread handle operations
OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (pOperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS currentProc = PsGetCurrentProcess();
    HANDLE callerPid = PsGetProcessId(currentProc);

    PETHREAD targetThread = (PETHREAD)pOperationInformation->Object;
    PEPROCESS targetProc = PsGetThreadProcess(targetThread);

    if (!targetProc) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE targetPid = PsGetProcessId(targetProc);

    if (callerPid == targetPid) {
        return OB_PREOP_SUCCESS; // Allow self-access
    }

    BOOLEAN callerIsProtected = IsProtectedProcessByPid(callerPid);
    BOOLEAN targetIsProtected = IsProtectedProcessByPid(targetPid);

    // Protected process accesses others -> grant extra access
    if (callerIsProtected && !targetIsProtected) {
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess |= PROCESS_ALL_ACCESS;
        }
    }

    // **GRANT FULL THREAD ACCESS TO HYDRADRAGON AV ONLY**
    if (callerIsProtected && targetIsProtected) {
        DbgPrint("[Process-Protection] Granting HydraDragonAV full thread access: PID %llu -> protected PID %llu\r\n",
            (unsigned long long)(ULONG_PTR)callerPid, (unsigned long long)(ULONG_PTR)targetPid);

        // Grant full access
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = THREAD_ALL_ACCESS;
        }
        else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = THREAD_ALL_ACCESS;
        }

        return OB_PREOP_SUCCESS;
    }

    // Main protection: External -> Protected (strip dangerous access)
    if (!callerIsProtected && targetIsProtected) {
        ACCESS_MASK DesiredAccess = 0;
        PCWSTR AttackType = NULL;

        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            DesiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            AttackType = L"THREAD_OPEN_BLOCKED";
        }
        else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            DesiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
            AttackType = L"THREAD_DUPLICATE_BLOCKED";
        }

        if ((DesiredAccess & THREAD_DANGEROUS_MASK) && AttackType) {
            DbgPrint("[Process-Protection] STRIPPING DANGEROUS THREAD ACCESS from PID %llu to protected PID %llu\r\n",
                (unsigned long long)(ULONG_PTR)callerPid, (unsigned long long)(ULONG_PTR)targetPid);

            QueueProcessAlertToUserMode(targetProc, currentProc, AttackType);

            // Strip dangerous access rights
            if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_DANGEROUS_MASK;
            }
            else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_DANGEROUS_MASK;
            }
        }
    }

    // Always return success for older WDKs; we only modify access rights.
    return OB_PREOP_SUCCESS;
}

//
// --- Helper Functions ---
//

// CHECKS: Checks if a PID is in our protected list. (Fast)
BOOLEAN IsProtectedProcessByPid(HANDLE ProcessId) {
    BOOLEAN isProtected = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ProtectedPidsLock, &lockHandle);

    PLIST_ENTRY pCurrent = g_ProtectedPidsList.Flink;
    while (pCurrent != &g_ProtectedPidsList) {
        PPROTECTED_PID_ENTRY pEntry = CONTAINING_RECORD(pCurrent, PROTECTED_PID_ENTRY, ListEntry);
        if (pEntry->ProcessId == ProcessId) {
            isProtected = TRUE;
            break;
        }
        pCurrent = pCurrent->Flink;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return isProtected;
}

// CHECKS: Checks if a process path is one we should protect. (Slower, used only at process creation)
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process) {
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer) {
        if (pImageName) ExFreePool(pImageName);
        return FALSE;
    }

    // Define the paths of the executables to be protected
    static const PCWSTR patterns[] = {
        L"\\Owlyshield Service\\owlyshield_ransom.exe",
        L"\\HydraDragonAntivirus\\HydraDragonAntivirusLauncher.exe",
        L"\\Sanctum\\sanctum_ppl_runner.exe",
        L"\\sanctum\\app.exe",
        L"\\sanctum\\server.exe",
        L"\\sanctum\\um_engine.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(patterns); ++i) {
        if (UnicodeStringEndsWithInsensitive(pImageName, patterns[i])) {
            result = TRUE;
            break;
        }
    }

    ExFreePool(pImageName);
    return result;
}


// Case-insensitive check to see if 'Source' string ENDS WITH 'Pattern'.
BOOLEAN UnicodeStringEndsWithInsensitive(PUNICODE_STRING Source, PCWSTR Pattern) {
    if (!Source || !Source->Buffer || !Pattern) return FALSE;

    UNICODE_STRING patternString;
    RtlInitUnicodeString(&patternString, Pattern);

    if (Source->Length < patternString.Length) return FALSE;

    // Create a temporary UNICODE_STRING for the suffix of the source string
    UNICODE_STRING sourceSuffix;
    sourceSuffix.Length = patternString.Length;
    sourceSuffix.MaximumLength = patternString.Length;
    sourceSuffix.Buffer = (PWCH)((PCHAR)Source->Buffer + Source->Length - patternString.Length);

    return (RtlCompareUnicodeString(&sourceSuffix, &patternString, TRUE) == 0);
}

//
// --- User-Mode Alerting ---
// (No changes needed in this section)
//

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

    if (!NT_SUCCESS(status))
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
