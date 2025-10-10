// Driver_Process.c  -- updated OB callback with path-based protection
#include <ntifs.h>
#include "Driver_Process.h"

PVOID obHandle;

// forward
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process);
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process);
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern);

// Entry / register
NTSTATUS ProcessDriverEntry()
{
    ProtectProcess();
    return STATUS_SUCCESS;
}

NTSTATUS ProtectProcess()
{
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&obReg, sizeof(obReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");

    // register for process handle create & duplicate
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;

    obReg.OperationRegistration = &opReg;

    return ObRegisterCallbacks(&obReg, &obHandle);
}

OB_PREOP_CALLBACK_STATUS preCall(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // get process id from the object (object is EPROCESS)
    HANDLE pidHandle = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
    PEPROCESS targetProc = NULL;

    if (!pidHandle)
        return OB_PREOP_SUCCESS;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pidHandle, &targetProc)))
        return OB_PREOP_SUCCESS;

    // Check protection either by full path substrings or by image filename
    if (IsProtectedProcessByPath(targetProc) || IsProtectedProcessByImageName(targetProc))
    {
        // handle create
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            // use CreateHandleInformation for CREATE
            ULONG orig = (ULONG)pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

            // zero out dangerous access in DesiredAccess
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_SESSIONID;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_PROCESS;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_LIMITED_INFORMATION;
            pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

            // logic based on OriginalDesiredAccess (same as your previous logic)
            if ((orig == PROCESS_TERMINATE_0) ||
                (orig == PROCESS_TERMINATE_1) ||
                (orig == PROCESS_KILL_F))
            {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x0;
            }
            if (orig == 0x1041)
            {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL;
            }
        }

        // handle duplicate
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            // use DuplicateHandleInformation for DUPLICATE
            ULONG orig = (ULONG)pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_SESSIONID;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_PROCESS;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_QUOTA;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SET_LIMITED_INFORMATION;
            pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

            if ((orig == PROCESS_TERMINATE_0) ||
                (orig == PROCESS_TERMINATE_1) ||
                (orig == PROCESS_KILL_F))
            {
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0x0;
            }
            if (orig == 0x1041)
            {
                pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = STANDARD_RIGHTS_ALL;
            }
        }
    }

    ObDereferenceObject(targetProc);
    return OB_PREOP_SUCCESS;
}

// Checks if the process image full path contains any of our interesting substrings.
// Note: SeLocateProcessImageName allocates the returned UNICODE_STRING buffer; free it with ExFreePool.
BOOLEAN IsProtectedProcessByPath(PEPROCESS Process)
{
    PUNICODE_STRING pImageName = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    // SeLocateProcessImageName returns allocated UNICODE_STRING (free with ExFreePool)
    status = SeLocateProcessImageName(Process, &pImageName);
    if (!NT_SUCCESS(status) || !pImageName || !pImageName->Buffer)
    {
        if (pImageName)
            ExFreePool(pImageName);
        return FALSE;
    }

    // Patterns to match (not full hardcoded absolute paths; substring-based)
    static const PCWSTR patterns[] = {
        L"\\HydraDragonAntivirus\\",
        L"\\hydradragon\\",
        L"\\Owlyshield Service\\",
        L"\\owlyshield_ransom.exe",
        L"\\Sanctum\\",
        L"\\sanctum_ppl_runner.exe",
        L"\\app.exe",
        L"\\server.exe",
        L"\\um_engine.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(patterns); ++i)
    {
        if (UnicodeStringContainsInsensitive(pImageName, patterns[i]))
        {
            result = TRUE;
            break;
        }
    }

    ExFreePool(pImageName); // free what SeLocateProcessImageName allocated
    return result;
}

// Fallback: still protect by image file name (PsGetProcessImageFileName returns ANSI 15-char name)
BOOLEAN IsProtectedProcessByImageName(PEPROCESS Process)
{
    PUCHAR name = PsGetProcessImageFileName(Process);
    if (!name)
        return FALSE;

    // list of exact filenames we also protect
    const char* names[] = {
        "HydraDragonAntivirusService.exe",
        "owlyshield_ransom.exe",
        "sanctum_ppl_runner.exe",
        "app.exe",
        "server.exe",
        "um_engine.exe"
    };

    for (ULONG i = 0; i < ARRAYSIZE(names); ++i)
    {
        if (_stricmp((const char*)name, names[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Case-insensitive substring search using RtlUpcaseUnicodeString.
// Returns TRUE if 'Pattern' is found inside 'Source' (case-insensitive).
BOOLEAN UnicodeStringContainsInsensitive(PUNICODE_STRING Source, PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || !Pattern)
        return FALSE;

    UNICODE_STRING srcU = *Source;
    UNICODE_STRING patU;
    RtlInitUnicodeString(&patU, Pattern);

    // Make uppercase copies (RtlUpcaseUnicodeString will allocate if third param TRUE)
    UNICODE_STRING srcUp, patUp;
    RtlZeroMemory(&srcUp, sizeof(srcUp));
    RtlZeroMemory(&patUp, sizeof(patUp));

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, &srcU, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &patU, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcLen = srcUp.Length / sizeof(WCHAR);
    ULONG patLen = patUp.Length / sizeof(WCHAR);

    if (patLen > 0 && patLen <= srcLen)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;

        for (ULONG i = 0; i + patLen <= srcLen; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patLen * sizeof(WCHAR)))
            {
                found = TRUE;
                break;
            }
        }
    }

    RtlFreeUnicodeString(&srcUp);
    RtlFreeUnicodeString(&patUp);
    return found;
}

NTSTATUS ProcessDriverUnload()
{
    if (obHandle)
        ObUnRegisterCallbacks(obHandle);
    return STATUS_SUCCESS;
}
