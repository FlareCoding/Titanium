#include "Injection.h"
#include "IoctlStructs.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos; // driver registration path

LIST_ENTRY TitaniumProcessInformationListHead;
#define TITANIUM_PROCESS_INFO_MEMORY_TAG ' TII'

typedef struct _TitaniumTargetImageInfo
{
	LIST_ENTRY  ListEntry;
	wchar_t*	Name[512];
	ULONG		ProcessID;
	ULONG64		ImageBase;
	ULONG64		ImageSize;
} TitaniumTargetImageInfo, *PTitaniumTargetImageInfo;

extern NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern NTSTATUS PsLookupProcessByProcessId(
	HANDLE ProcessId,
	PEPROCESS* Process
);

PTitaniumTargetImageInfo CreateTitaniumProcessInfo(HANDLE ProcessId, wchar_t* Name)
{
	PTitaniumTargetImageInfo Info = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TitaniumTargetImageInfo), TITANIUM_PROCESS_INFO_MEMORY_TAG);

	RtlZeroMemory(Info, sizeof(TitaniumTargetImageInfo));
	Info->ProcessID = ProcessId;

	wcscpy(Info->Name, Name);

	InsertTailList(&TitaniumProcessInformationListHead, &Info->ListEntry);

	return Info;
}

PTitaniumTargetImageInfo FindTitaniumProcessInfoByPID(HANDLE ProcessID)
{
	PLIST_ENTRY NextEntry = TitaniumProcessInformationListHead.Flink;

	while (NextEntry != &TitaniumProcessInformationListHead)
	{
		PTitaniumTargetImageInfo ProcInfo = CONTAINING_RECORD(NextEntry, TitaniumTargetImageInfo, ListEntry);

		if (ProcInfo->ProcessID == ProcessID)
			return ProcInfo;

		NextEntry = NextEntry->Flink;
	}

	return NULL;
}

PTitaniumTargetImageInfo FindTitaniumProcessInfoByName(wchar_t* ProcessName)
{
	PLIST_ENTRY NextEntry = TitaniumProcessInformationListHead.Flink;

	while (NextEntry != &TitaniumProcessInformationListHead)
	{
		PTitaniumTargetImageInfo ProcInfo = CONTAINING_RECORD(NextEntry, TitaniumTargetImageInfo, ListEntry);

		if (wcsstr(ProcInfo->Name, ProcessName))
			return ProcInfo;

		NextEntry = NextEntry->Flink;
	}

	return NULL;
}

VOID RemoveTitaniumProcessInfo(HANDLE ProcessId)
{
	PTitaniumTargetImageInfo Info = FindTitaniumProcessInfoByPID(ProcessId);

	if (Info)
	{
		RemoveEntryList(&Info->ListEntry);
		ExFreePoolWithTag(Info, TITANIUM_PROCESS_INFO_MEMORY_TAG);
	}
}

NTSTATUS ReadVirtualProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS WriteVirtualProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

void PloadImageNotifyRoutine(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo
)
{
	PTitaniumTargetImageInfo ProcessInfo = FindTitaniumProcessInfoByName(FullImageName->Buffer);

	if (!ProcessInfo)
		ProcessInfo = CreateTitaniumProcessInfo(ProcessId, FullImageName->Buffer);

	ProcessInfo->ImageBase = (ULONG64)(ImageInfo->ImageBase);
	ProcessInfo->ImageSize = (ULONG64)(ImageInfo->ImageSize);

	Injector_OnLoadImageNotifyRoutine(FullImageName, ProcessId, ImageInfo);
}

void PcreateProcessNotifyRoutine(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
)
{
	if (!Create)
	{
		while (FindTitaniumProcessInfoByPID(ProcessId))
			RemoveTitaniumProcessInfo(ProcessId);
	}

	Injector_OnProcessCreateRoutine(ParentId, ProcessId, Create);
}

void PcreateThreadNotifyRoutine(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create
)
{
	if (!Create) return;
}

NTSTATUS IoctlControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status = 0;
	ULONG BytesIO	= 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG IoctlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	switch (IoctlCode)
	{
		// ======================================== //
		// ============ Reading Memory ============ //
		// ======================================== //
	case TITANIUM_MEMORY_READ_REQUEST_32BIT:
	{
		PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT input = (PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process = 0;
		NTSTATUS result = PsLookupProcessByProcessId(input->ProcessID, &Process);

		if (NT_SUCCESS(result))
			ReadVirtualProcessMemory(Process, (PVOID)input->pSource, (PVOID)input->pTarget, input->Size);

		BytesIO = sizeof(PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT);
		Status = STATUS_SUCCESS;
		break;
	}
	case TITANIUM_MEMORY_READ_REQUEST_64BIT:
	{
		PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT input = (PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process = 0;
		NTSTATUS result = PsLookupProcessByProcessId(input->ProcessID, &Process);

		if (NT_SUCCESS(result))
			ReadVirtualProcessMemory(Process, (PVOID)input->pSource, (PVOID)input->pTarget, input->Size);

		BytesIO = sizeof(PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT);
		Status = STATUS_SUCCESS;
		break;
	}
		// ======================================== //
		// ============ Writing Memory ============ //
		// ======================================== //
	case TITANIUM_MEMORY_WRITE_REQUEST_32BIT:
	{
		PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT input = (PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process = 0;
		NTSTATUS result = PsLookupProcessByProcessId(input->ProcessID, &Process);

		if (NT_SUCCESS(result))
			WriteVirtualProcessMemory(Process, input->pSource, input->pTarget, input->Size);

		BytesIO = sizeof(PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT);
		Status = STATUS_SUCCESS;
		break;
	}
	case TITANIUM_MEMORY_WRITE_REQUEST_64BIT:
	{
		PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT input = (PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process = 0;
		NTSTATUS result = PsLookupProcessByProcessId(input->ProcessID, &Process);

		if (NT_SUCCESS(result))
			WriteVirtualProcessMemory(Process, input->pSource, input->pTarget, input->Size);

		BytesIO = sizeof(PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT);
		Status = STATUS_SUCCESS;
		break;
	}
		// ====================================================== //
		// ============ Retrieving Target Image Info ============ //
		// ====================================================== //
	case TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_32BIT:
	{
		PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT input = (PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT)Irp->AssociatedIrp.SystemBuffer;

		PTitaniumTargetImageInfo Info = FindTitaniumProcessInfoByName((PVOID)input->pProcessName);
		if (Info)
		{
			UsermodeTitaniumTargetImageInfo UsermodeInfo;
			UsermodeInfo.ProcessID = Info->ProcessID;
			UsermodeInfo.ImageBase = Info->ImageBase;
			UsermodeInfo.ImageSize = Info->ImageSize;

			*((UsermodeTitaniumTargetImageInfo*)input->pTargetImageInfo) = UsermodeInfo;
		}

		BytesIO = sizeof(PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT);
		Status = STATUS_SUCCESS;
		break;
	}
	case TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_64BIT:
	{
		PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT input = (PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT)Irp->AssociatedIrp.SystemBuffer;

		PTitaniumTargetImageInfo Info = FindTitaniumProcessInfoByName((PVOID)input->pProcessName);
		if (Info)
		{
			UsermodeTitaniumTargetImageInfo UsermodeInfo;
			UsermodeInfo.ProcessID = Info->ProcessID;
			UsermodeInfo.ImageBase = Info->ImageBase;
			UsermodeInfo.ImageSize = Info->ImageSize;

			*((UsermodeTitaniumTargetImageInfo*)input->pTargetImageInfo) = UsermodeInfo;
		}

		BytesIO = sizeof(PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT);
		Status = STATUS_SUCCESS;
		break;
	}
		// ====================================================== //
		// ==================== DLL Injection =================== //
		// ====================================================== //
	case TITANIUM_INJECT_X64_DLL_REQUEST_64BIT:
	{
		PTITANIUM_KERNEL_INJECT_X64_DLL_REQUEST_64BIT input = (PTITANIUM_KERNEL_INJECT_X64_DLL_REQUEST_64BIT)Irp->AssociatedIrp.SystemBuffer;

		wchar_t LocalDLLPathBuffer[512];
		wcscpy(LocalDLLPathBuffer, (PVOID)input->pDLLPathBuffer);

		ULONG64 BaseAddress = InjectX64Dll(input->ProcessID, LocalDLLPathBuffer);
		*((ULONG64*)input->pBaseAddress) = BaseAddress;

		BytesIO = sizeof(PTITANIUM_KERNEL_INJECT_X64_DLL_REQUEST_64BIT);
		Status = STATUS_SUCCESS;
		break;
	}
	default: 
	{
		Status = STATUS_INVALID_PARAMETER;
		break; 
	}
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("[+] Titanium Driver Successfully Unloaded [+]\r\n");

	PsRemoveCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);

	return STATUS_SUCCESS;
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT pDriverObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("[+] Titanium Driver Entry [+]\r\n");

	InitializeListHead(&TitaniumProcessInformationListHead);
	Injector_InitializeInjectionInfo();

	PsSetLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, FALSE);
	PsSetCreateThreadNotifyRoutine(PcreateThreadNotifyRoutine);

	RtlInitUnicodeString(&dev, L"\\Device\\titanium");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\titanium");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlControl;
	pDriverObject->DriverUnload = Unload;

	pDriverObject->Flags |= DO_DIRECT_IO;
	pDriverObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}
