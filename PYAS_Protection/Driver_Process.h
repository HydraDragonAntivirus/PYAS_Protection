

#include<ntifs.h>

//进程管理器结束代码
#define PROCESS_TERMINATE_0       0x1001
//taskkill指令结束代码
#define PROCESS_TERMINATE_1       0x0001 
//taskkill指令加/f参数强杀进程结束码
#define PROCESS_KILL_F			  0x1401

extern UCHAR* PsGetProcessImageFileName
(
	_In_ PEPROCESS Process
);

//设置回调
NTSTATUS ProtectProcess();

//根据进程pid获取进程名
char* GetProcessImageNameByProcessID
(
	_In_ ULONG ulProcessID
);

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
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                 (0x0001)
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME            (0x0002)
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT               (0x0008)
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT               (0x0010)
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION           (0x0020)
#endif
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
#define THREAD_SET_LIMITED_INFORMATION   (0x0400)
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)
#endif
