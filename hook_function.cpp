#include "function_defeniton.h"

BOOL WriteFile_engine(HANDLE hFile, LPCVOID lpBuffer)
{
	static BOOL isHook = FALSE;
	static _WriteFile _pWriteFile = NULL;
	
	if (!isHook)
	{
		SecureZeroMemory(&_hookInfo, sizeof(_HOOKINFO));
		
		_pWriteFile = (_WriteFile)_initialize(djb2_values[1], "WriteFile", 0x0);

		DWORD _newFunction = _inithook(0x2, (unsigned char*)_hookWriteFile); //0x0 print disass, give function address

		_originalWriteFile = (_WriteFile)_hookInfo._newFunction;

		isHook = TRUE;

	}
	DWORD written = 0;
	BOOL ret = _pWriteFile(hFile, lpBuffer, strlen((const char*)lpBuffer), &written, 0x0);

	return ret;
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
	int _hookDataLen = strlen((const char*)_msg);

	//printf_s("Original Write File lpBuffer : %s \n", lpBuffer);

	strcpy((char*)_hookData, (const char*)lpBuffer); //API HOOKING
	strcat((char*)_hookData, (const char*)_msg); //API HOOKING ON WINDOWS 10 :)

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