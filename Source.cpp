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

	BOOL ret = WriteFile_engine(hFile,lpBuffer);

	CloseHandle(hFile);
}

