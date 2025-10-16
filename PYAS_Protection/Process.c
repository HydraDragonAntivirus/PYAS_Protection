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
// globals
static POB_CALLBACK_REGISTRATION g_ObReg = NULL;
static POB_OPERATION_REGISTRATION g_OpReg = NULL;

NTSTATUS ProtectProcess(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    // Safety: ensure called at PASSIVE_LEVEL
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("ProtectProcess: wrong IRQL %u\n", (ULONG)KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }

    // Init list/spinlock (assuming globals declared elsewhere)
    InitializeListHead(&g_ProtectedPidsList);
    KeInitializeSpinLock(&g_ProtectedPidsLock);

    // Register process notify first (optional, but keep your behavior)
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
        return status;
    }

    // Allocate heap registrations (use NonPagedPoolNx)
    g_OpReg = (POB_OPERATION_REGISTRATION)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(OB_OPERATION_REGISTRATION) * 2, 'gOpR');
    if (!g_OpReg) {
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_OpReg, sizeof(OB_OPERATION_REGISTRATION) * 2);

    g_ObReg = (POB_CALLBACK_REGISTRATION)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(OB_CALLBACK_REGISTRATION), 'gObR');
    if (!g_ObReg) {
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        g_OpReg = NULL;
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_ObReg, sizeof(OB_CALLBACK_REGISTRATION));

    // Fill g_OpReg
    g_OpReg[0].ObjectType = PsProcessType;
    g_OpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[0].PreOperation = preCall;
    g_OpReg[0].PostOperation = NULL;

    g_OpReg[1].ObjectType = PsThreadType;
    g_OpReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OpReg[1].PreOperation = threadPreCall;
    g_OpReg[1].PostOperation = NULL;

    // Fill g_ObReg
    g_ObReg->Version = ObGetFilterVersion();
    g_ObReg->OperationRegistrationCount = 2;
    g_ObReg->OperationRegistration = g_OpReg;
    g_ObReg->RegistrationContext = NULL;
    RtlInitUnicodeString(&g_ObReg->Altitude, L"321000");

    // Single, correct registration
    status = ObRegisterCallbacks(g_ObReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Process-Protection] ObRegisterCallbacks failed: 0x%X\n", status);
        ExFreePoolWithTag(g_OpReg, 'gOpR');
        ExFreePoolWithTag(g_ObReg, 'gObR');
        g_OpReg = NULL;
        g_ObReg = NULL;
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
        return status;
    }

    DbgPrint("[Process-Protection] ObRegisterCallbacks succeeded\n");
    return STATUS_SUCCESS;
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

// CALLBACK: Intercepts process handle operations (improved - preserves resume bits)
OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // If it's a kernel handle, skip
    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();
    HANDLE callerPid = PsGetProcessId(currentProc);
    PEPROCESS targetProc = (PEPROCESS)pOperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProc);

    // Always allow self-access
    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;

    BOOLEAN callerIsProtected = IsProtectedProcessByPid(callerPid);
    BOOLEAN targetIsProtected = IsProtectedProcessByPid(targetPid);

    // If the target is not protected, leave normal processing
    if (!targetIsProtected)
        return OB_PREOP_SUCCESS;

    // If caller is protected, grant full access
    if (callerIsProtected)
    {
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
        else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;

        return OB_PREOP_SUCCESS;
    }

    // Caller not protected, target protected -> inspect desired access
    ACCESS_MASK DesiredAccess = 0;
    ACCESS_MASK OrigAccess = 0;

    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        DesiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        OrigAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }
    else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        DesiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        OrigAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess; // fallback
    }

    // Bits we must NOT strip because they are needed for process startup/resume
    const ACCESS_MASK PreserveProcessBits = PROCESS_SUSPEND_RESUME | SYNCHRONIZE;

    if (DesiredAccess & PROCESS_DANGEROUS_MASK)
    {
        // Debug print
        DbgPrint("preCall(PROC): caller=%u target=%u op=%u desired=0x%X orig=0x%X\n",
            (ULONG)(ULONG_PTR)callerPid, (ULONG)(ULONG_PTR)targetPid,
            (ULONG)pOperationInformation->Operation, (ULONG)DesiredAccess, (ULONG)OrigAccess);

        // Alert user-mode (queues work item - safe)
        QueueProcessAlertToUserMode(targetProc, currentProc, L"PROCESS_ACCESS_BLOCKED");

        // Only clear dangerous bits that are NOT in PreserveProcessBits
        ACCESS_MASK ToClear = PROCESS_DANGEROUS_MASK & ~PreserveProcessBits;

        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~ToClear;
        }
        else {
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~ToClear;
        }
    }

    // Special-case restore (retain your existing 0x1041 handling if needed)
    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        int code = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        if (code == 0x1041) {
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL | PROCESS_ALL_ACCESS;
        }
    }

    return OB_PREOP_SUCCESS;
}


// CALLBACK: Intercepts thread handle operations (improved - preserves resume bits)
OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (pOperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    PEPROCESS currentProc = PsGetCurrentProcess();
    HANDLE callerPid = PsGetProcessId(currentProc);

    PETHREAD targetThread = (PETHREAD)pOperationInformation->Object;
    PEPROCESS targetProc = PsGetThreadProcess(targetThread);

    if (!targetProc)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId(targetProc);

    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;

    BOOLEAN callerIsProtected = IsProtectedProcessByPid(callerPid);
    BOOLEAN targetIsProtected = IsProtectedProcessByPid(targetPid);

    if (!targetIsProtected)
        return OB_PREOP_SUCCESS;

    // If caller is protected, grant full thread access
    if (callerIsProtected)
    {
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = THREAD_ALL_ACCESS;
        else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = THREAD_ALL_ACCESS;

        return OB_PREOP_SUCCESS;
    }

    // Caller not protected, target protected -> inspect desired access
    ACCESS_MASK DesiredAccess = 0;
    if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        DesiredAccess = pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        DesiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

    // Bits we must not strip for threads (so parent/system can resume/initialize thread)
    const ACCESS_MASK PreserveThreadBits = THREAD_SUSPEND_RESUME | SYNCHRONIZE;

    if (DesiredAccess & THREAD_DANGEROUS_MASK)
    {
        DbgPrint("preCall(THREAD): caller=%u target=%u op=%u desired=0x%X\n",
            (ULONG)(ULONG_PTR)callerPid, (ULONG)(ULONG_PTR)targetPid,
            (ULONG)pOperationInformation->Operation, (ULONG)DesiredAccess);

        QueueProcessAlertToUserMode(targetProc, currentProc, L"THREAD_ACCESS_BLOCKED");

        ACCESS_MASK ToClear = THREAD_DANGEROUS_MASK & ~PreserveThreadBits;

        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~ToClear;
        else
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~ToClear;
    }

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
