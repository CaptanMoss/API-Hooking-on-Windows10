#pragma once
#pragma warning(disable : 4996)
#include <wtypes.h>

#include "hook.h"
#include "ldr.h"


BOOL WriteFile_engine(HANDLE hFile,LPCVOID lpBuffer);

typedef  BOOL(WINAPI* _WriteFile)( //WriteFile strucre
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

BOOL WINAPI _hookWriteFile( //hooked Write File Function
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

_WriteFile _originalWriteFile = NULL;