#pragma once

#include <windows.h>

#include "SharpStruct.h"
#include "Structs.h"

/* ------------------------
	Globals
------------------------ */

typedef void(WINAPI* fnExec)(void*);

/* ------------------------
	Stub.s
------------------------ */

extern VOID	HellsGate(
	_In_	DWORD	wSyscall,
	_In_	PVOID	pJmpAddr
);

extern NTSTATUS	HellDescent(
);

/* ------------------------
	Utils.c
------------------------ */

BOOL ReadFileFromDisk(
	_In_		LPCSTR	lpFilePath,
	_Inout_		PVOID*	pAddr,
	_Inout_		PDWORD	dwSize
);

clrVersion GetVersionOfClr(
	_In_		PVOID	fileContent,
	_In_		DWORD	fileSize
);

BOOL CheckIfClrIsLoaded(
	_In_		clrVersion			version,
	_In_		IEnumUnknown*		pEnumerator,
	_In_		ICLRRuntimeInfo*	pRuntimeInfo
);

SAFEARRAY* prepareArgs(
	_In_		LPWSTR		lpwArgs
);

BOOL SolveHookAddr(
	_In_	PHOOK_ADDR	hookList
);

DWORD64 dwFindRetInstruction(
	_In_	DWORD64		dwAddr
);

DWORD64 dwFindRetInstruction(
	_In_	DWORD64		dwAddr
);

BOOL GetSyscall(
	_In_	PVOID		pFunctionAddress,
	_In_	PSYS_INFO	sysInfo
);


/* ------------------------
	Execute.c
------------------------ */

BOOL executeAssembly(
	_In_	PVOID		pAssemblyContent,
	_In_	DWORD		dwAssemblySize,
	_In_	LPWSTR		lpwAssemblyArgs
);

/* ------------------------
	Hooks.c
------------------------ */

LONG HookHandler(
	_In_	PEXCEPTION_POINTERS		ExceptionInfo
);

BOOL SetHwbp(
	_In_	HANDLE	hThread,
	_In_	DWORD64	dwAddr1,
	_In_	DWORD64	dwAddr2,
	_In_	DWORD64	dwAddr3,
	_In_	DWORD64	dwAddr4
);

BOOL PutHwbpInAllThreads(
	_In_	DWORD	dwPid
);

/* ------------------------
	Patch.c
------------------------ */

BOOL PatchFunction(
	_In_	PVOID	pFunctionAddr,
	_In_	BOOL	needRwx
);