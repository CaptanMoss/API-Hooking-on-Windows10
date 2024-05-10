# API Hooking on Windows 10

## Overview

API Hooking on Windows 10 is an engine designed to facilitate the hooking of APIs on the Windows 10 operating system. It provides a reliable mechanism for intercepting function calls and modifying their behavior.

## Features

- **Dynamic DLL Loading**: The engine utilizes the DJB2 hash value for dynamic DLL loading, enhancing efficiency and flexibility.
- **Function Address Resolution**: Function addresses in memory are resolved using the LDR structure, ensuring accurate and reliable hooking.
- **Improved Stability**: The engine offers more stable hooking of functions in the 32-bit architecture, resulting in enhanced performance and compatibility.

## Usage

1. **Clone the Repository**: Clone the API Hooking on Windows 10 repository: https://github.com/CaptanMoss/API-Hooking-on-Windows10.git
2. 2. **Build the Engine**: Open the project with Visual Studio and build it.
3. **Integrate with Your Project**: Incorporate the engine into your project and utilize the provided API hooking functionality.

## Example Code

```c
#include <stdio.h>
#include <Windows.h>
#include "function_defeniton.h"


int main(int argc, char** argv)
{

	HANDLE hFile = CreateFile(L"NewFile.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW || OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("%d\n", GetLastError());
		ExitProcess(0);
	}

	LPCVOID  lpBuffer = "API HOOKING ";
	LPDWORD  lpNumberOfBytesWritten = 0;

	BOOL ret = WriteFile_engine(hFile,lpBuffer); //hooked function

	CloseHandle(hFile);
}

```
## Contributing
🤝 Contributions are welcome! If you'd like to contribute to this project, please open a pull request or create an issue to discuss your suggestions.
