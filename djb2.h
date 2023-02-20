#pragma once
#include <Windows.h>

	static unsigned int djb2_values[12] = { 0x22d3b5ed,0x7040ee75,0x2722e788,0x5a6bd3f3,0xe092e076,0x721d7aaa,0x9ad10b0f,0x67208a49,0x60c3db35,0xf92c2394,0xecf21d5a,0x7d5e04ec };
	//static const char* const values[] = {"NTDLL.DLL","KERNEL32.DLL","GDI32.DLL","USER32.DLL","COMCTL32.DLL","COMDLG32.DLL","WS2_32.DLL","ADVAPI32.DLL","NETAPI32.DLL","OLE32.DLL","MSVCRT.DLL,","ucrtbased.dll",};

	extern DWORD __cdecl djb2(unsigned int* dll_hash, PWSTR word);
