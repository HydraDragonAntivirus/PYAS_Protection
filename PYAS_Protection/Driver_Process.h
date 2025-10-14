#pragma once

#include<ntifs.h>

//进程管理器结束代码
#define PROCESS_TERMINATE_0       0x1001
//taskkill指令结束代码
#define PROCESS_TERMINATE_1       0x0001 
//taskkill指令加/f参数强杀进程结束码
#define PROCESS_KILL_F			  0x1401

//设置回调
NTSTATUS ProtectProcess();

//回调函数
OB_PREOP_CALLBACK_STATUS preCall
(
	_In_ PVOID Context,
	_In_ POB_PRE_OPERATION_INFORMATION Opation
);
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)
// Thread access rights definitions
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION         (0x0040)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN          (0x0080)
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE               (0x0100)
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION      (0x0200)
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#endif

//
// --- Globals for PID Tracking ---
//

// Structure for our linked list entries
typedef struct _PROTECTED_PID_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
} PROTECTED_PID_ENTRY, * PPROTECTED_PID_ENTRY;

LIST_ENTRY g_ProtectedPidsList;
KSPIN_LOCK g_ProtectedPidsLock;
PVOID g_ObRegistrationHandle;

// Alerting (Worker thread)
typedef struct _PROCESS_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING TargetPath;
    UNICODE_STRING AttackerPath;
    HANDLE TargetPid;
    HANDLE AttackerPid;
    WCHAR AttackType[64];
} PROCESS_ALERT_WORK_ITEM, * PPROCESS_ALERT_WORK_ITEM;

// Process protection functions
NTSTATUS ProcessDriverEntry();
NTSTATUS ProcessDriverUnload();
NTSTATUS ProtectProcess();

// Callbacks
OB_PREOP_CALLBACK_STATUS preCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);
OB_PREOP_CALLBACK_STATUS threadPreCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);
VOID CreateProcessNotifyRoutine(_In_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID ProcessAlertWorker(PVOID Context);

// Helper functions
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process);
BOOLEAN IsProtectedProcessByPid(HANDLE ProcessId);
BOOLEAN UnicodeStringEndsWithInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);

#define SELF_DEFENSE_PIPE_NAME L"\\??\\pipe\\self_defense_alerts"
#define PID_LIST_TAG 'diPP' // Pool tag for our PID list allocations

//
// --- Forward Declarations ---
//

// Core logic
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process);
BOOLEAN IsProtectedProcessByPid(HANDLE ProcessId);
OB_PREOP_CALLBACK_STATUS preCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);
OB_PREOP_CALLBACK_STATUS threadPreCall(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);

// Helpers
BOOLEAN UnicodeStringEndsWithInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);
BOOLEAN IsCallerLauncher(PEPROCESS Proc);
NTSTATUS QueueProcessAlertToUserMode(PEPROCESS TargetProcess, PEPROCESS AttackerProcess, PCWSTR AttackType);

// Safety masks
#define PROCESS_SAFE_MASK (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
#define PROCESS_DANGEROUS_MASK (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | \
                                PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION | \
                                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | \
                                PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | \
                                PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_SET_LIMITED_INFORMATION)

#define THREAD_SAFE_MASK (THREAD_QUERY_INFORMATION | SYNCHRONIZE)
#define THREAD_DANGEROUS_MASK (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | \
                               THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                               THREAD_DIRECT_IMPERSONATION)
