// Driver.c - Main driver entry with integrated protections (Windows 10 x64 ONLY)
#include "Driver.h"

// Global device object for work items
PDEVICE_OBJECT g_DeviceObject = NULL;

// Bypass signature check
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
    typedef struct _KLDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY listEntry;
        ULONG64 __Undefined1;
        ULONG64 __Undefined2;
        ULONG64 __Undefined3;
        ULONG64 NonPagedDebugInfo;
        ULONG64 DllBase;
        ULONG64 EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG   Flags;
        USHORT  LoadCount;
        USHORT  __Undefined5;
        ULONG64 __Undefined6;
        ULONG   CheckSum;
        ULONG   __padding1;
        ULONG   TimeDateStamp;
        ULONG   __padding2;
    } KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

    PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
    pLdrData->Flags = pLdrData->Flags | 0x20;
    return TRUE;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT PDO,
    _In_ PUNICODE_STRING STR
)
{
    UNREFERENCED_PARAMETER(STR);
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    PLDR_DATA_TABLE_ENTRY64 ldr;

    DbgPrint("[Driver] ================================================\r\n");
    DbgPrint("[Driver] SimplePYASProtection Driver Loading...\r\n");
    DbgPrint("[Driver] Target: Windows 10 x64\r\n");
    DbgPrint("[Driver] ================================================\r\n");

    // Bypass signature check
    BypassCheckSign(PDO);

    // Bypass MmVerifyCallbackFunction
    ldr = (PLDR_DATA_TABLE_ENTRY64)PDO->DriverSection;
    ldr->Flags |= 0x20;

    // Create device object for work items
    RtlInitUnicodeString(&deviceName, L"\\Device\\SimplePYASProtection");

    status = IoCreateDevice(
        PDO,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Driver] Failed to create device: 0x%X\r\n", status);
        return status;
    }

    // Create symbolic link
    RtlInitUnicodeString(&symbolicLink, L"\\??\\SimplePYASProtection");
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Driver] Failed to create symbolic link: 0x%X\r\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    // Set unload routine
    PDO->DriverUnload = DriverUnload;

    // ========================================================
    // Initialize Service Protection FIRST (self-defense)
    // ========================================================
    DbgPrint("[Driver] [1/4] Initializing Service Protection...\r\n");
    status = InitializeServiceProtection();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Driver] WARNING: Service protection failed: 0x%X\r\n", status);
        DbgPrint("[Driver] Continuing without service protection...\r\n");
    }
    else
    {
        DbgPrint("[Driver] [+] Service Protection: ACTIVE (sc stop BLOCKED)\r\n");
    }

    // ========================================================
    // Initialize Process Protection
    // ========================================================
    DbgPrint("[Driver] [2/4] Initializing Process Protection...\r\n");
    status = ProcessDriverEntry(g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Driver] Process protection failed: 0x%X\r\n", status);
        goto Cleanup;
    }
    DbgPrint("[Driver] [+] Process Protection: ACTIVE\r\n");

    // ========================================================
    // Initialize File Protection
    // ========================================================
    DbgPrint("[Driver] [3/4] Initializing File Protection...\r\n");
    status = FileDriverEntry();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Driver] File protection failed: 0x%X\r\n", status);
        goto Cleanup;
    }
    DbgPrint("[Driver] [+] File Protection: ACTIVE\r\n");

    // ========================================================
    // Initialize Registry Protection
    // ========================================================
    DbgPrint("[Driver] [4/4] Initializing Registry Protection...\r\n");
    status = RegeditDriverEntry();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[Driver] Registry protection failed: 0x%X\r\n", status);
        goto Cleanup;
    }
    DbgPrint("[Driver] [+] Registry Protection: ACTIVE\r\n");

    DbgPrint("[Driver] ================================================\r\n");
    DbgPrint("[Driver] ALL PROTECTIONS INITIALIZED SUCCESSFULLY!\r\n");
    DbgPrint("[Driver] ================================================\r\n");
    DbgPrint("[Driver] Driver is now SELF-PROTECTED from:\r\n");
    DbgPrint("[Driver]   [x] sc stop/delete/config commands\r\n");
    DbgPrint("[Driver]   [x] Registry modifications\r\n");
    DbgPrint("[Driver]   [x] Process termination attempts\r\n");
    DbgPrint("[Driver]   [x] File system tampering\r\n");
    DbgPrint("[Driver] ================================================\r\n");

    return STATUS_SUCCESS;

Cleanup:
    DbgPrint("[Driver] Initialization failed, cleaning up...\r\n");
    CleanupServiceProtection();
    ProcessDriverUnload();
    FileUnloadDriver();
    RegeditUnloadDriver();

    if (g_DeviceObject)
    {
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    return status;
}

NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT pdo)
{
    UNREFERENCED_PARAMETER(pdo);
    UNICODE_STRING symbolicLink;

    DbgPrint("[Driver] ================================================\r\n");
    DbgPrint("[Driver] Unloading driver...\r\n");
    DbgPrint("[Driver] ================================================\r\n");

    // Cleanup all protections in reverse order
    DbgPrint("[Driver] [1/4] Cleaning up Service Protection...\r\n");
    CleanupServiceProtection();

    DbgPrint("[Driver] [2/4] Cleaning up Registry Protection...\r\n");
    RegeditUnloadDriver();

    DbgPrint("[Driver] [3/4] Cleaning up File Protection...\r\n");
    FileUnloadDriver();

    DbgPrint("[Driver] [4/4] Cleaning up Process Protection...\r\n");
    ProcessDriverUnload();

    // Delete device and symbolic link
    if (g_DeviceObject)
    {
        RtlInitUnicodeString(&symbolicLink, L"\\??\\SimplePYASProtection");
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[Driver] ================================================\r\n");
    DbgPrint("[Driver] Driver unloaded successfully\r\n");
    DbgPrint("[Driver] ================================================\r\n");

    return STATUS_SUCCESS;
}
