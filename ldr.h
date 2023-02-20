#pragma once 
#include <Windows.h>
#include <subauth.h>

	DWORD _findDllAddress(unsigned int dll);

	DWORD _findFunctionAddress(DWORD dll, LPCSTR function);

	DWORD string_compare(PWSTR param1, PWSTR param2);

	void _LoadLibrary(wchar_t ldrstring[]);

	typedef NTSTATUS(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
	typedef NTSTATUS(NTAPI* _LdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

