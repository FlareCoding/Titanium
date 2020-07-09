# Titanium

Titanium is a library consisting of a driver and interface that allows to read and write memory, acquire process IDs and module addresses, all on the kernel level.

## Platform
Titanium is currently only supported on Windows 10.

## Installation

The driver is not yet signed, so you will have to put your Windows 10 into test mode and load the driver using a tool like OSRLoader.

The interface files are Titanium.h and Titanium.cpp located in the Titanium source folder. Add them to your project to use them.

## Sample Code

The following code waits until Sandbox.exe image loads, prints out the base address and module size, and injects a dll using APC injection.

```cpp
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
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
