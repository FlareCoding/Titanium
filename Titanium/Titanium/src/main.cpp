#include <iostream>
#include <string>
#include <thread>

#include "Titanium/Titanium.h"

int main()
{
	TitaniumInterface ti;

	std::wstring name = L"Sandbox.exe";

	ULONG pid = 0;
	while (!pid)
	{
		auto module = ti.GetTargetImageInfo(name.c_str());
		pid = module.ProcessID;

		if (pid == 0) std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	auto module = ti.GetTargetImageInfo(name.c_str());
	std::cout << "Image Info 0:\n";
	std::cout << "    PID    : " << module.ProcessID << "\n";
	std::cout << "    Base   : " << module.ImageBase << "\n";
	std::cout << "    Size   : " << module.ImageSize << "\n";
	std::cout << "\n-------------------------\n\n";

	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	ULONG64 base = ti.InjectX64DLL(module.ProcessID, L"C:\\Users\\alber\\Desktop\\TestDLL.dll");
	std::cout << "DLL Injected at 0x" << std::hex << base << std::dec << "\n";

	system("pause");
	return 0;
}
