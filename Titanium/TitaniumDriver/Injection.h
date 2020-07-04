#pragma once
#include "KernelDecls.h"

typedef struct _TITANIUM_INJECTION_INFO
{
	LIST_ENTRY ListEntry;
	HANDLE ProcessId;
	PLDR_LOAD_DLL LdrLoadDllRoutine;
	UNICODE_STRING DllPath;
	PVOID DllBase; // If successfully injected, will be the address of the injected dll
	BOOLEAN Injected; // Injection status
} TITANIUM_INJECTION_INFO, *PTITANIUM_INJECTION_INFO;

VOID Injector_InitializeInjectionInfo();
VOID Injector_OnLoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
VOID Injector_OnProcessCreateRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

ULONG64 InjectX64Dll(HANDLE ProcessId, wchar_t* dllpath);
