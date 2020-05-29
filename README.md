# Titanium

Titanium is a library consisting of a driver and interface that allows to read and write memory, acquire process IDs and module addresses, all on the kernel level.

## Platform
Titanium is currently only supported on Windows 10.

## Installation

The driver is not yet signed, so you will have to put your Windows 10 into test mode and load the driver using a tool like OSRLoader.

The interface files are Titanium.h and Titanium.cpp located in the Titanium source folder. Add them to your project to use them.

## Sample Code

The following code sets two target images and checks until they load after which it prints out their respective base addresses, sizes, and process IDs.

```cpp
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
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
