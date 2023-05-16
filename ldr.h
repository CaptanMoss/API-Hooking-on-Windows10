#ifdef __cplusplus
extern "C" {
#endif

#pragma once 
#include <Windows.h>
#include <NTSecAPI.h>
	//#include <winternl.h>

	DWORD _initialize(unsigned int dll_hash, LPCSTR  lpProcName, BOOL ishook);
	DWORD _inithook(int _control, unsigned char* _hookFuncAddres);

	DWORD _findDllAddress(unsigned int dll);

	DWORD _findFunctionAddress(DWORD dll, LPCSTR function);

	DWORD string_compare(PWSTR param1, PWSTR param2);

	void _LoadLibrary(const wchar_t* ldrstring);

	static unsigned int djb2_values[] = { 0x22d3b5ed,0x7040ee75,0x2722e788,0x5a6bd3f3,0xe092e076,0x721d7aaa,0x9ad10b0f,0x67208a49,0x60c3db35,0xf92c2394,0xecf21d5a,0x7d5e04ec,0x87594a69,0x8dbd9c6d,0x12956686 };
	//static const char* const values[] = {"NTDLL.DLL","KERNEL32.DLL","GDI32.DLL","USER32.DLL","COMCTL32.DLL","COMDLG32.DLL","WS2_32.DLL","ADVAPI32.DLL","NETAPI32.DLL","OLE32.DLL","MSVCRT.DLL,","ucrtbased.dll","combase.dll","Crypt32.dll"};
	typedef NTSTATUS(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
	typedef NTSTATUS(NTAPI* _LdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

	DWORD djb2(unsigned int* dll_hash, PWSTR word);

#ifdef __cplusplus
}
#endif
