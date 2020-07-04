#include "Injection.h"
#include <ntimage.h>

// -------------------------------------------- //
// ----------------- GLOBALS ------------------ //

#define TITANIUM_MEMORY_TAG ' tiI'

LIST_ENTRY InjectionInformationListHead;

ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");

extern VOID NormalRoutineNativeAssembly(PVOID Context, PVOID SysArg1, PVOID SysArg2);

// -------------------------------------------- //
// -------------------------------------------- //
// ------------------ PRIVATE ----------------- //

PTITANIUM_INJECTION_INFO CreateInjectionInfo(HANDLE ProcessId)
{
    PTITANIUM_INJECTION_INFO Info = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TITANIUM_INJECTION_INFO), TITANIUM_MEMORY_TAG);

    RtlZeroMemory(Info, sizeof(TITANIUM_INJECTION_INFO));
    Info->ProcessId = ProcessId;

    InsertTailList(&InjectionInformationListHead, &Info->ListEntry);

    return Info;
}

PTITANIUM_INJECTION_INFO FindInjectionInfo(HANDLE ProcessId)
{
    PLIST_ENTRY NextEntry = InjectionInformationListHead.Flink;

    while (NextEntry != &InjectionInformationListHead)
    {
        PTITANIUM_INJECTION_INFO InjectionInfo = CONTAINING_RECORD(NextEntry, TITANIUM_INJECTION_INFO, ListEntry);

        if (InjectionInfo->ProcessId == ProcessId)
            return InjectionInfo;

        NextEntry = NextEntry->Flink;
    }

    return NULL;
}

VOID RemoveInjectionInfo(HANDLE ProcessId)
{
    PTITANIUM_INJECTION_INFO Info = FindInjectionInfo(ProcessId);

    if (Info)
    {
        RemoveEntryList(&Info->ListEntry);
        ExFreePoolWithTag(Info, TITANIUM_MEMORY_TAG);
    }
}

PVOID FindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName)
{
    PULONG NameTable;
    PUSHORT OrdinalTable;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    LONG Low = 0, Mid = 0, High, Ret;
    USHORT Ordinal;
    PVOID Function;
    ULONG ExportSize;
    PULONG ExportTable;

    // Get the export directory.
    ExportDirectory = RtlImageDirectoryEntryToData(
        DllBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &ExportSize
    );

    // Setup name tables
    NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
    OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

    // Binary search
    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low)
    {
        Mid = (Low + High) >> 1;
        Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);

        if (Ret < 0)
            High = Mid - 1;
        else if (Ret > 0)
            Low = Mid + 1;
        else
            break;
    }

    if (High < Low)
        return NULL;

    Ordinal = OrdinalTable[Mid];

    // Validate the ordinal.
    if (Ordinal >= ExportDirectory->NumberOfFunctions)
        return NULL;

    // Resolve the address and write it
    ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
    Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

    return Function;
}

VOID KernelApc(PVOID Context, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4)
{
    ExFreePool(Context);
}

VOID InjectorAPCNormalRoutine(PVOID Context, PVOID SysArg1, PVOID SysArg2)
{
    PTITANIUM_INJECTION_INFO InjectionInfo = (PTITANIUM_INJECTION_INFO)Context;
    
    InjectionInfo->LdrLoadDllRoutine(NULL, 0, &InjectionInfo->DllPath, &InjectionInfo->DllBase);
    InjectionInfo->Injected = TRUE;
}

VOID NRStubFn() {}

PETHREAD FindAvailableThread(HANDLE ProcessId)
{
    PVOID buffer = ExAllocatePool(NonPagedPool, 1024 * 1024); // Allocate memory for the system information
    if (!buffer)
    {
        DbgPrint("Error: Unable to allocate memory for the process thread list.\n");
        return NULL;
    }

    // Get the process thread list
    if (!NT_SUCCESS(ZwQuerySystemInformation(5, buffer, 1024 * 1024, NULL)))
    {
        DbgPrint("Error: Unable to query process thread list.\n");

        ExFreePool(buffer);
        return NULL;
    }

    PSYSTEM_PROCESS_INFO pSpi = (PSYSTEM_PROCESS_INFO)buffer;

    // Find a target thread
    while (pSpi->NextEntryOffset)
    {
        if (pSpi->UniqueProcessId == ProcessId)
        {
            //DbgPrint("Target thread found. TID: %d\n", pSpi->Threads[0].ClientId.UniqueThread);
            break;
        }

        pSpi = (PSYSTEM_PROCESS_INFO)((PUCHAR)pSpi + pSpi->NextEntryOffset);
    }

    // Reference the target process
    PEPROCESS Process = NULL;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
    {
        DbgPrint("Error: Unable to reference the target process.\n");

        ExFreePool(buffer);
        return NULL;
    }

    // Reference the target thread
    PETHREAD Thread = NULL;

    if (!NT_SUCCESS(PsLookupThreadByThreadId(pSpi->Threads[0].ClientId.UniqueThread, &Thread)))
    {
        DbgPrint("Error: Unable to reference the target thread.\n");
        ObDereferenceObject(Process); // Dereference the target process

        ExFreePool(buffer);
        return NULL;
    }

    ExFreePool(buffer); // Free the allocated memory

    return Thread;
}

// -------------------------------------------- //
// -------------------------------------------- //
// ------------------ PUBLIC ------------------ //

VOID Injector_InitializeInjectionInfo()
{
	InitializeListHead(&InjectionInformationListHead);
}

VOID Injector_OnLoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    // Loads in x64 processes
    if (wcsstr(FullImageName->Buffer, L"\\System32\\ntdll.dll"))
    {
        PVOID LdrLoadDllRoutineAddress = FindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDllRoutineName);
        PTITANIUM_INJECTION_INFO InjectionInfo = FindInjectionInfo(ProcessId);

        InjectionInfo->LdrLoadDllRoutine = (PLDR_LOAD_DLL)LdrLoadDllRoutineAddress;
    }
}

VOID Injector_OnProcessCreateRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (Create)
        CreateInjectionInfo(ProcessId);
    else
        RemoveInjectionInfo(ProcessId);
}

ULONG64 InjectX64Dll(HANDLE ProcessId, wchar_t* dllpath)
{
    PTITANIUM_INJECTION_INFO InjectionInfo = FindInjectionInfo(ProcessId);

    PEPROCESS pProcess;
    PsLookupProcessByProcessId(ProcessId, &pProcess);

    PETHREAD AvailableThread = FindAvailableThread(ProcessId);
    if (!AvailableThread)
    {
        DbgPrint("Failed to find available thread in target process\n\n");
        return 0;
    }

    KeAttachProcess(pProcess);

    PVOID DllPathBufferAddress = NULL;
    SIZE_T DllPathBufferAddressSize = 1024;

    NTSTATUS status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&DllPathBufferAddress, 0, &DllPathBufferAddressSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] Failed to allocate memory for dll path buffer, error code: 0x%X [-]\n", status);
        KeDetachProcess();
        DbgPrint("Detached from process\n\n");

        return 0;
    }

    wcscpy(DllPathBufferAddress, dllpath);

    PTITANIUM_INJECTION_INFO ContextAddress = NULL;
    SIZE_T ContextAllocationSize = 4096;

    status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&ContextAddress, 0, &ContextAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] Failed to allocate memory for apc context, error code: 0x%X [-]\n", status);
        KeDetachProcess();
        DbgPrint("Detached from process\n\n");

        return 0;
    }
    
    memcpy(ContextAddress, InjectionInfo, sizeof(TITANIUM_INJECTION_INFO));

    ContextAddress->DllPath.Buffer = (PWCH)DllPathBufferAddress;
    RtlInitUnicodeString(&ContextAddress->DllPath, ContextAddress->DllPath.Buffer);

    PVOID  NormalRoutineAddress = NULL;
    SIZE_T NormalRoutineAllocationSize = (SIZE_T)((ULONG_PTR)NRStubFn - (ULONG_PTR)InjectorAPCNormalRoutine);

    status = ZwAllocateVirtualMemory(NtCurrentProcess(), &NormalRoutineAddress, 0, &NormalRoutineAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] Failed to allocate memory for apc normal routine [-]\n");
        KeDetachProcess();
        DbgPrint("Detached from process\n\n");

        return 0;
    }

    memcpy(NormalRoutineAddress, NormalRoutineNativeAssembly, NormalRoutineAllocationSize);

    PKAPC apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
    if (!apc)
    {
        DbgPrint("Error: Unable to allocate the APC object.");
        KeDetachProcess();
        DbgPrint("Detached from process\n");
        return 0;
    }

    KeInitializeApc(apc, AvailableThread, OriginalApcEnvironment, KernelApc, NULL, (PKNORMAL_ROUTINE)NormalRoutineAddress, UserMode, ContextAddress);
    KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

    LARGE_INTEGER delay;
    delay.QuadPart = -200 * 10000;

    while (!((PTITANIUM_INJECTION_INFO)ContextAddress)->Injected)
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

    ULONG64 BaseAddress = (ULONG64)((PTITANIUM_INJECTION_INFO)ContextAddress)->DllBase;
    
    SIZE_T size = 0;

    ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&DllPathBufferAddress,  &size,  MEM_RELEASE);
    ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&ContextAddress,        &size,  MEM_RELEASE);
    ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&NormalRoutineAddress,  &size,  MEM_RELEASE);

    KeDetachProcess();

    ObDereferenceObject(pProcess); // Dereference the target process
    ObDereferenceObject(AvailableThread); // Dereference the target thread

    return BaseAddress;
}
