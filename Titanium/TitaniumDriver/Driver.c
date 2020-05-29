#include <ntddk.h>
#include <wdm.h>
#include "IoctlStructs.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos; // driver registration path

#define MAX_TARGET_IMAGES 10

typedef struct _TitaniumTargetImageInfo
{
	ULONG		ProcessID;
	ULONG64		ImageBase;
	ULONG64		ImageSize;
} TitaniumTargetImageInfo;

typedef struct _TargetImage
{
	// Image name to be looking for in the LoadImageNotifyRoutine
	wchar_t* TargetImageName[128];

	TitaniumTargetImageInfo Info;
} TargetImage;

static TargetImage s_TargetImages[MAX_TARGET_IMAGES] = { 0 };

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
	for (int i = 0; i < MAX_TARGET_IMAGES; i++)
	{
		if (wcsstr(FullImageName->Buffer, s_TargetImages[i].TargetImageName))
		{
			s_TargetImages[i].Info.ProcessID = (ULONG64)((PVOID)ProcessId);
			s_TargetImages[i].Info.ImageBase = (ULONG64)(ImageInfo->ImageBase);
			s_TargetImages[i].Info.ImageSize = (ULONG64)(ImageInfo->ImageSize);
		}
	}
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
		// ============================================== //
		// ============ Setting Target Image ============ //
		// ============================================== //
	case TITANIUM_SET_TARGET_IMAGE_REQUEST_32BIT:
	{
		PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST_32BIT input = (PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST_32BIT)Irp->AssociatedIrp.SystemBuffer;

		memcpy_s(s_TargetImages[input->ImageIndex].TargetImageName, input->TargetImageBufferSize, (wchar_t*)input->pTargetImageBuffer, input->TargetImageBufferSize);

		BytesIO = sizeof(PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST_32BIT);
		Status = STATUS_SUCCESS;
		break;
	}
	case TITANIUM_SET_TARGET_IMAGE_REQUEST_64BIT:
	{
		PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST_64BIT input = (PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST_64BIT)Irp->AssociatedIrp.SystemBuffer;

		memcpy_s(s_TargetImages[input->ImageIndex].TargetImageName, input->TargetImageBufferSize, (wchar_t*)input->pTargetImageBuffer, input->TargetImageBufferSize);

		BytesIO = sizeof(PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST_64BIT);
		Status = STATUS_SUCCESS;
		break;
	}
		// ====================================================== //
		// ============ Retrieving Target Image Info ============ //
		// ====================================================== //
	case TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_32BIT:
	{
		PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT input = (PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT)Irp->AssociatedIrp.SystemBuffer;

		// Check if process still exists
		PEPROCESS Process = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(s_TargetImages[input->ImageIndex].Info.ProcessID, &Process)))
		{
			s_TargetImages[input->ImageIndex].Info.ProcessID = 0;
			s_TargetImages[input->ImageIndex].Info.ImageBase = 0;
			s_TargetImages[input->ImageIndex].Info.ImageSize = 0;
		}

		*((TitaniumTargetImageInfo*)input->pTargetImageInfo) = s_TargetImages[input->ImageIndex].Info;

		BytesIO = sizeof(PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT);
		Status = STATUS_SUCCESS;
		break;
	}
	case TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_64BIT:
	{
		PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT input = (PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT)Irp->AssociatedIrp.SystemBuffer;

		// Check if process still exists
		PEPROCESS Process = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(s_TargetImages[input->ImageIndex].Info.ProcessID, &Process)))
		{
			s_TargetImages[input->ImageIndex].Info.ProcessID = 0;
			s_TargetImages[input->ImageIndex].Info.ImageBase = 0;
			s_TargetImages[input->ImageIndex].Info.ImageSize = 0;
		}

		*((TitaniumTargetImageInfo*)input->pTargetImageInfo) = s_TargetImages[input->ImageIndex].Info;

		BytesIO = sizeof(PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT);
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

	for (int i = 0; i < MAX_TARGET_IMAGES; i++)
	{
		RtlZeroMemory(&s_TargetImages[i], sizeof(TargetImage));
		memcpy_s(s_TargetImages[i].TargetImageName, 11, L"noimgloaded", 11);
	}

	PsSetLoadImageNotifyRoutine(PloadImageNotifyRoutine);

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
