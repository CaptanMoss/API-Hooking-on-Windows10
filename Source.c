#include <stdio.h>
#include <Windows.h>

#include "initial.h"
#include "hook.h"
#include "djb2.h"


typedef  BOOL(WINAPI* _WriteFile)( //WriteFile strucre
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_	LPOVERLAPPED lpOverlapped
	);

BOOL WINAPI _hookWriteFile( //hooked Write File Function
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

_WriteFile _originalWriteFile = NULL;


int main(int argc, char** argv)
{
	DWORD _oldFunction = _initialize(djb2_values[1], "WriteFile");//argument1:DLL Hash, argument2:Function return orginal function address

	DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookWriteFile); //0x0 print disass, give function address

	_originalWriteFile = _hookInfo._newFunction;

	HANDLE hFile = CreateFile(L"NewFile.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW || OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	LPCVOID  lpBuffer = "API HOOKING ";
	LPDWORD  lpNumberOfBytesWritten = 0;

	WriteFile(hFile, lpBuffer, strlen(lpBuffer), &lpNumberOfBytesWritten, NULL);


	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("%d\n", GetLastError());
		ExitProcess(0);
	}

	CloseHandle(hFile);
}

BOOL WINAPI _hookWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	const void* _msg = "ON WINDOWS 10 :)";

	int _size = (nNumberOfBytesToWrite + 0x40) * sizeof(char);
	void* _hookData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _size);
	int _hookDataLen = strlen(_msg);

	//printf_s("Original Write File lpBuffer : %s \n", lpBuffer);

	strcpy(_hookData, lpBuffer); //API HOOKING
	strcat(_hookData, (const char*)_msg); //API HOOKING ON WINDOWS 10 :)

	BOOL result;
	result = _originalWriteFile(hFile, _hookData, nNumberOfBytesToWrite + _hookDataLen, lpNumberOfBytesWritten, lpOverlapped);

	if (result)
	{
		*lpNumberOfBytesWritten -= _hookDataLen;
	}
	else
	{
		printf_s("Unsuccessful API Hooking\n");
	}

	HeapFree(GetProcessHeap(), 0, _hookData);

	return result;
}