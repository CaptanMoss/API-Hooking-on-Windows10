

#pragma once
#pragma warning(disable : 4996)

#include <stdio.h>
#include <Windows.h>


DWORD _initialize(unsigned int dll_hash, LPCSTR  lpProcName, BOOL ishook);
DWORD _inithook(int _control, unsigned char* _hookFuncAddres);

