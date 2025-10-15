#pragma once

#include <ntifs.h>

//
// --- Constants and Definitions ---
//

#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"
#define PID_LIST_TAG 'diPP' // Pool tag for our PID list allocations

// Process access rights considered dangerous
#define PROCESS_DANGEROUS_MASK (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | \
                                PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION | \
                                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | \
                                PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | \
                                PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_SET_LIMITED_INFORMATION)

// Thread access rights considered dangerous
#define THREAD_DANGEROUS_MASK (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | \
                               THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                               THREAD_DIRECT_IMPERSONATION)

//
// --- Structures ---
//

// Structure for our linked list entries to track protected PIDs
typedef struct _PROTECTED_PID_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
} PROTECTED_PID_ENTRY, * PPROTECTED_PID_ENTRY;

// Structure for passing alert data to a worker thread
typedef struct _PROCESS_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING TargetPath;
    UNICODE_STRING AttackerPath;
    HANDLE TargetPid;
    HANDLE AttackerPid;
    WCHAR AttackType[64];
} PROCESS_ALERT_WORK_ITEM, * PPROCESS_ALERT_WORK_ITEM;


//
// --- Function Prototypes ---
//

// Main driver functions
NTSTATUS ProcessDriverEntry();
NTSTATUS ProcessDriverUnload();
NTSTATUS ProtectProcess();

// Kernel callbacks
VOID CreateProcessNotifyRoutine(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

OB_PREOP_CALLBACK_STATUS threadPreCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

// Worker thread for user-mode alerting
VOID ProcessAlertWorker(
    PVOID Context
);

// Helper functions
BOOLEAN IsProtectedProcessByPath(
    PEPROCESS Process
);

BOOLEAN IsProtectedProcessByPid(
    HANDLE ProcessId
);

BOOLEAN UnicodeStringEndsWithInsensitive(
    PUNICODE_STRING Source,
    PCWSTR Pattern
);

NTSTATUS QueueProcessAlertToUserMode(
    PEPROCESS TargetProcess,
    PEPROCESS AttackerProcess,
    PCWSTR AttackType
);
