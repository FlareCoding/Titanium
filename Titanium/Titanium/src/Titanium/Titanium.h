#pragma once
#include <Windows.h>

#include <cstdint>
#include <string>

#if INTPTR_MAX == INT32_MAX
#define TITANIUM_X86
#elif INTPTR_MAX == INT64_MAX
#define TITANIUM_X64
#else
#error "Environment not 32 or 64-bit."
#endif

struct TitaniumTargetImageInfo
{
	ULONG		ProcessID;
	ULONG64		ImageBase;
	ULONG64		ImageSize;
};

class TitaniumInterface
{
public:
	TitaniumInterface();
	~TitaniumInterface();

#ifdef TITANIUM_X86
	void ReadVirtualMemory(ULONG ProcessID, ULONG SourceAddr, void* TargetAddr, ULONG Size);
	void WriteVirtualMemory(ULONG ProcessID, void* SourceAddr, ULONG TargetAddr, ULONG Size);
	void SetTargetImageName(wchar_t* name, UINT32 length, UINT32 index);
	TitaniumTargetImageInfo GetTargetImageInfo(UINT32 index);
#endif

#ifdef TITANIUM_X64
	void ReadVirtualMemory(ULONG64 ProcessID, ULONG64 SourceAddr, void* TargetAddr, ULONG64 Size);
	void WriteVirtualMemory(ULONG64 ProcessID, void* SourceAddr, ULONG64 TargetAddr, ULONG64 Size);
	void SetTargetImageName(wchar_t* name, UINT32 length, UINT32 index);
	TitaniumTargetImageInfo GetTargetImageInfo(UINT32 index);
#endif

private:
	HANDLE hDriver;
};

class TitaniumMemory
{
public:
	TitaniumInterface& GetDriverInterface() { return iface; }

#ifdef TITANIUM_X86
	template <typename T>
	T Read(ULONG pid, ULONG address)
	{
		T val;
		iface.ReadVirtualMemory(pid, address, &val, sizeof(T));
		return val;
	}

	template <typename T>
	void Write(ULONG pid, ULONG address, T value)
	{
		iface.WriteVirtualMemory(pid, &value, address, sizeof(T));
	}

	ULONG PatternScan(ULONG pid, ULONG start, ULONG size, const std::string& pattern);
#endif

#ifdef TITANIUM_X64
	template <typename T>
	T Read(ULONG pid, ULONG64 address)
	{
		T val;
		iface.ReadVirtualMemory(pid, address, &val, sizeof(T));
	}

	template <typename T>
	void Write(ULONG pid, ULONG64 address, T value)
	{
		iface.WriteVirtualMemory(pid, &value, address, sizeof(T));
	}

	ULONG64 PatternScan(ULONG pid, ULONG64 start, ULONG64 size, const std::string& pattern);
#endif

private:
	TitaniumInterface iface;

private:
	bool CompareMemory(const BYTE* bData, const BYTE* bMask, const char* szMask);
	void CreateSignatureAndMask(const std::string& pattern, std::string& signature, std::string& mask);
};
