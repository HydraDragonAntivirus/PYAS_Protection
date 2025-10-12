#include "Driver.h"

// Bypass driver signature enforcement
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
#ifdef _WIN64
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
#else
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG unknown1;
		ULONG unknown2;
		ULONG unknown3;
		ULONG unknown4;
		ULONG unknown5;
		ULONG unknown6;
		ULONG unknown7;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

	PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	pLdrData->Flags |= 0x20;

	return TRUE;
}

// DriverEntry
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObj,
	_In_ PUNICODE_STRING pRegistryString
)
{
	UNREFERENCED_PARAMETER(pRegistryString);

	BypassCheckSign(pDriverObj);
	pDriverObj->DriverUnload = DriverUnload;

#if _WIN64
	PLDR_DATA_TABLE_ENTRY64 ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
#else
	PLDR_DATA_TABLE_ENTRY32 ldr = (PLDR_DATA_TABLE_ENTRY32)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
#endif

	// Initialize core modules
	ProcessDriverEntry();
	FileDriverEntry();
	RegeditDriverEntry();

	// Initialize service protection
	NTSTATUS status = InitializeServiceProtection();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[Driver] Failed to initialize service protection: 0x%X\n", status);
	}
	else
	{
		DbgPrint("[Driver] Service protection initialized successfully\n");
	}

	return STATUS_SUCCESS;
}

// DriverUnload
NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT pDriverObj)
{
	UNREFERENCED_PARAMETER(pDriverObj);

	// Cleanup service protection
	CleanupServiceProtection();

	// Cleanup other modules
	ProcessDriverUnload();
	FileUnloadDriver();
	RegeditUnloadDriver();

	return STATUS_SUCCESS;
}
