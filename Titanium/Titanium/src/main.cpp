#include <iostream>
#include <string>
#include <thread>

#include "Titanium/Titanium.h"

int main()
{
	TitaniumInterface ti;

	std::wstring name1 = L"\\csgo\\bin\\client_panorama.dll";
	std::wstring name2 = L"\\bin\\engine.dll";

	ti.SetTargetImageName((wchar_t*)name1.c_str(), name1.size(), 0);
	printf("\nTarget Image [%i] set to: %ws\n", 0, name1.c_str());

	ti.SetTargetImageName((wchar_t*)name2.c_str(), name2.size(), 1);
	printf("Target Image [%i] set to: %ws\n\n", 1, name2.c_str());

	ULONG pid = 0;
	while (!pid)
	{
		auto client_info = ti.GetTargetImageInfo(0);

		std::cout << "Image Info 0 (Client):\n";
		std::cout << "    PID    : " << client_info.ProcessID << "\n";
		std::cout << "    Base   : " << client_info.ImageBase << "\n";
		std::cout << "    Size   : " << client_info.ImageSize << "\n\n";

		auto engine_info = ti.GetTargetImageInfo(1);
		std::cout << "Image Info 1 (Engine):\n";
		std::cout << "    PID    : " << engine_info.ProcessID << "\n";
		std::cout << "    Base   : " << engine_info.ImageBase << "\n";
		std::cout << "    Size   : " << engine_info.ImageSize << "\n";

		std::cout << "\n-------------------------\n";
		std::this_thread::sleep_for(std::chrono::seconds(1));

		pid = client_info.ProcessID;
	}

	system("pause");
	return 0;
}
