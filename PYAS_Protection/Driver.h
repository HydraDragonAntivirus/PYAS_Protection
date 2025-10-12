// Driver.h - Windows 10 x64 ONLY
#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>
#include <ntstrsafe.h>

// Windows 10 x64 LDR_DATA_TABLE_ENTRY structure
typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

// Process access rights constants
#define PROCESS_TERMINATE_0 0x1
#define PROCESS_TERMINATE_1 0x1000
#define PROCESS_KILL_F 0xFFFF

// Global device object for work items
extern PDEVICE_OBJECT g_DeviceObject;

// Driver entry and unload
NTSTATUS DriverEntry
(
    _In_ PDRIVER_OBJECT PDO,
    _In_ PUNICODE_STRING STR
);

NTSTATUS DriverUnload
(
    _In_ PDRIVER_OBJECT pdo
);

// Process protection module
NTSTATUS ProcessDriverEntry(PDEVICE_OBJECT DeviceObject);
NTSTATUS ProcessDriverUnload();
NTSTATUS ProtectProcess();
OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
);

// File protection module
NTSTATUS FileDriverEntry();
VOID FileUnloadDriver();

// Registry protection module
NTSTATUS RegeditDriverEntry();
NTSTATUS RegeditUnloadDriver();

// Service protection module (NEW)
NTSTATUS InitializeServiceProtection();
VOID CleanupServiceProtection();

#endif // DRIVER_H
