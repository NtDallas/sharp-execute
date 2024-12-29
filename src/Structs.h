#pragma once

typedef enum _clrVersion {
	CLR_V2,
	CLR_V4
} clrVersion;

typedef struct _HOOK_ADDR {
	void*	AmsiScanBuffer;
	void*	NtTraceEvent;
	void*	NtCreateThreadEx;
	void*	NtCreateWorkerFactory;
	void*	QueueUserWorkItem;
} HOOK_ADDR, *PHOOK_ADDR;

typedef struct _SYS_INFO {
	void*	pAddress;
	WORD    syscall;
} SYS_INFO, * PSYS_INFO;
