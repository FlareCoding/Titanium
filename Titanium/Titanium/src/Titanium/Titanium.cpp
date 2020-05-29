#include "Titanium.h"

#define TITANIUM_MEMORY_READ_REQUEST_32BIT					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4554, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_MEMORY_WRITE_REQUEST_32BIT					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4584, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define TITANIUM_MEMORY_READ_REQUEST_64BIT					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7554, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_MEMORY_WRITE_REQUEST_64BIT					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7584, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define TITANIUM_SET_TARGET_IMAGE_REQUEST_32BIT				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4694, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_SET_TARGET_IMAGE_REQUEST_64BIT				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7694, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_32BIT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4310, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_64BIT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7310, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#ifdef TITANIUM_X86
typedef struct _TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST
{
	ULONG ProcessID;
	ULONG pSource;
	ULONG pTarget;
	ULONG Size;
} TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST, *PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST;

typedef struct _TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST
{
	UINT32	ImageIndex;
	ULONG	pTargetImageBuffer;
	UINT32	TargetImageBufferSize;
} TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST, *PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST;

typedef struct _TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST
{
	UINT32	ImageIndex;
	ULONG	pTargetImageInfo;
} TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST, *PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST;
#endif // TITANIUM_X86

#ifdef TITANIUM_X64
typedef struct _TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST
{
	ULONG64 ProcessID;
	ULONG64 pSource;
	ULONG64 pTarget;
	ULONG64 Size;
} TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST, *PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST;

typedef struct _TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST
{
	UINT32	ImageIndex;
	ULONG64	pTargetImageBuffer;
	UINT32	TargetImageBufferSize;
} TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST, *PTITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST;

typedef struct _TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST
{
	UINT32	ImageIndex;
	ULONG64	pTargetImageInfo;
} TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST, *PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST;
#endif // TITANIUM_X64

TitaniumInterface::TitaniumInterface()
{
	hDriver = CreateFileA("\\\\.\\titanium", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
}

TitaniumInterface::~TitaniumInterface()
{
	CloseHandle(hDriver);
}

#ifdef TITANIUM_X86
void TitaniumInterface::ReadVirtualMemory(ULONG ProcessID, ULONG SourceAddr, void* TargetAddr, ULONG Size)
{
	TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST req;
	req.ProcessID = ProcessID;
	req.pSource = SourceAddr;
	req.pTarget = (ULONG)TargetAddr;
	req.Size = Size;

	DeviceIoControl(hDriver, TITANIUM_MEMORY_READ_REQUEST_32BIT, &req, sizeof(TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST), 0, 0, 0, 0);
}

void TitaniumInterface::WriteVirtualMemory(ULONG ProcessID, void* SourceAddr, ULONG TargetAddr, ULONG Size)
{
	TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST req;
	req.ProcessID = ProcessID;
	req.pSource = (ULONG)SourceAddr;
	req.pTarget = TargetAddr;
	req.Size = Size;

	DeviceIoControl(hDriver, TITANIUM_MEMORY_WRITE_REQUEST_32BIT, &req, sizeof(TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST), 0, 0, 0, 0);
}

void TitaniumInterface::SetTargetImageName(wchar_t* name, UINT32 length, UINT32 index)
{
	TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST req;
	req.ImageIndex = (index < 0 || index > 9) ? 0 : index; // index must be between 0 and 9
	req.pTargetImageBuffer = (ULONG)name;
	req.TargetImageBufferSize = ((length > 128) ? 128 : length) * sizeof(wchar_t); // max size is 128

	DeviceIoControl(hDriver, TITANIUM_SET_TARGET_IMAGE_REQUEST_32BIT, &req, sizeof(TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST), 0, 0, 0, 0);
}

TitaniumTargetImageInfo TitaniumInterface::GetTargetImageInfo(UINT32 index)
{
	TitaniumTargetImageInfo info;

	TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST req;
	req.ImageIndex = (index < 0 || index > 9) ? 0 : index; // index must be between 0 and 9
	req.pTargetImageInfo = (ULONG)&info;

	DeviceIoControl(hDriver, TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_32BIT, &req, sizeof(TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST), 0, 0, 0, 0);

	return info;
}

ULONG TitaniumMemory::FindPatternArray(ULONG pid, ULONG start, ULONG size, const char* mask, int count, ...)
{
	char* sig = new char[count + 1];
	va_list ap;
	va_start(ap, count);

	for (int i = 0; i < count; i++)
	{
		char read = va_arg(ap, char);
		sig[i] = read;
	}

	va_end(ap);
	sig[count] = '\0';
	return FindPattern(pid, start, size, sig, mask);
}

ULONG TitaniumMemory::FindPattern(ULONG pid, ULONG start, ULONG size, const char* sig, const char* mask)
{
	BYTE* data = new BYTE[size];

	iface.ReadVirtualMemory(pid, start, data, size);

	for (ULONG i = 0; i < size; i++)
	{
		if (DataCompare((const BYTE*)(data + i), (const BYTE*)sig, mask))
		{
			delete[] sig;
			delete[] data;
			return start + i;
		}
	}

	delete[] sig;
	delete[] data;
	return NULL;
}
#endif // TITANIUM_X86

#ifdef TITANIUM_X64
void TitaniumInterface::ReadVirtualMemory(ULONG64 ProcessID, ULONG64 SourceAddr, void* TargetAddr, ULONG64 Size)
{
	TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST req;
	req.ProcessID = ProcessID;
	req.pSource = SourceAddr;
	req.pTarget = (ULONG64)TargetAddr;
	req.Size = Size;

	DeviceIoControl(hDriver, TITANIUM_MEMORY_READ_REQUEST_64BIT, &req, sizeof(TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST), 0, 0, 0, 0);
}

void TitaniumInterface::WriteVirtualMemory(ULONG64 ProcessID, void* SourceAddr, ULONG64 TargetAddr, ULONG64 Size)
{
	TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST req;
	req.ProcessID = ProcessID;
	req.pSource = (ULONG64)SourceAddr;
	req.pTarget = TargetAddr;
	req.Size = Size;

	DeviceIoControl(hDriver, TITANIUM_MEMORY_WRITE_REQUEST_64BIT, &req, sizeof(TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST), 0, 0, 0, 0);
}

void TitaniumInterface::SetTargetImageName(wchar_t* name, UINT32 length, UINT32 index)
{
	TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST req;
	req.ImageIndex = (index < 0 || index > 9) ? 0 : index; // index must be between 0 and 9
	req.pTargetImageBuffer = (ULONG64)name;
	req.TargetImageBufferSize = ((length > 128) ? 128 : length) * sizeof(wchar_t); // max size is 128

	DeviceIoControl(hDriver, TITANIUM_SET_TARGET_IMAGE_REQUEST_64BIT, &req, sizeof(TITANIUM_KERNEL_SET_TARGET_IMAGE_REQUEST), 0, 0, 0, 0);
}

TitaniumTargetImageInfo TitaniumInterface::GetTargetImageInfo(UINT32 index)
{
	TitaniumTargetImageInfo info;

	TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST req;
	req.ImageIndex = (index < 0 || index > 9) ? 0 : index; // index must be between 0 and 9
	req.pTargetImageInfo = (ULONG64)&info;

	DeviceIoControl(hDriver, TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_64BIT, &req, sizeof(TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST), 0, 0, 0, 0);

	return info;
}

ULONG64 TitaniumMemory::FindPatternArray(ULONG pid, ULONG64 start, ULONG64 size, const char* mask, int count, ...)
{
	char* sig = new char[count + 1];
	va_list ap;
	va_start(ap, count);

	for (int i = 0; i < count; i++)
	{
		char read = va_arg(ap, char);
		sig[i] = read;
	}

	va_end(ap);
	sig[count] = '\0';
	return FindPattern(pid, start, size, sig, mask);
}

ULONG64 TitaniumMemory::FindPattern(ULONG pid, ULONG64 start, ULONG64 size, const char* sig, const char* mask)
{
	BYTE* data = new BYTE[size];

	iface.ReadVirtualMemory(pid, start, data, size);

	for (ULONG64 i = 0; i < size; i++)
	{
		if (DataCompare((const BYTE*)(data + i), (const BYTE*)sig, mask))
		{
			delete[] sig;
			delete[] data;
			return start + i;
		}
	}

	delete[] sig;
	delete[] data;
	return NULL;
}
#endif // TITANIUM_X64

bool TitaniumMemory::DataCompare(const BYTE* pData, const BYTE* pMask, const char* pszMask)
{
	for (; *pszMask; ++pszMask, ++pData, ++pMask)
		if (*pszMask == 'x' && *pData != *pMask)
			return false;

	return (*pszMask == NULL);
}
