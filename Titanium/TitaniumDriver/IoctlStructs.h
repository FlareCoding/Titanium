#pragma once

#define TITANIUM_MEMORY_READ_REQUEST_32BIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4554, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_MEMORY_WRITE_REQUEST_32BIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4584, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define TITANIUM_MEMORY_READ_REQUEST_64BIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7554, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_MEMORY_WRITE_REQUEST_64BIT			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7584, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

typedef struct _TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT
{
	ULONG ProcessID;
	ULONG pSource;
	ULONG pTarget;
	ULONG Size;
} TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT, *PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_32BIT;

typedef struct _TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT
{
	ULONG64 ProcessID;
	ULONG64 pSource;
	ULONG64 pTarget;
	ULONG64 Size;
} TITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT, *PTITANIUM_KERNEL_MEMORY_READ_WRITE_REQUEST_64BIT;

#define TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_32BIT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4310, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_GET_TARGET_IMAGE_INFO_REQUEST_64BIT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7310, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

typedef struct _UsermodeTitaniumTargetImageInfo
{
	ULONG		ProcessID;
	ULONG64		ImageBase;
	ULONG64		ImageSize;
} UsermodeTitaniumTargetImageInfo;

typedef struct _TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT
{
	ULONG	pProcessName;
	ULONG	pTargetImageInfo;
} TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT, *PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_32BIT;

typedef struct _TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT
{
	ULONG64 pProcessName;
	ULONG64	pTargetImageInfo;
} TITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT, *PTITANIUM_KERNEL_GET_TARGET_IMAGE_INFO_REQUEST_64BIT;

#define TITANIUM_INJECT_X64_DLL_REQUEST_64BIT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1923, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define TITANIUM_INJECT_X86_DLL_REQUEST_64BIT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1925, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

typedef struct _TITANIUM_KERNEL_INJECT_DLL_REQUEST_64BIT
{
	ULONG	ProcessID;
	ULONG64 pDLLPathBuffer;
	ULONG64 pBaseAddress;
} TITANIUM_KERNEL_INJECT_DLL_REQUEST_64BIT, *PTITANIUM_KERNEL_INJECT_DLL_REQUEST_64BIT;
