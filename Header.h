#pragma once
#pragma warning(disable : 4996)
#include <stdio.h>
#include <Windows.h>
#include <errhandlingapi.h>
#include <stdint.h>

#if defined(__x86_64__) || defined(_M_X64) 
#include "capstonex64/include/capstone/capstone.h"
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#include "capstonex86/include/capstone/capstone.h"
#endif


#define JMPOPCODE 0x25FF
#define _JMP 0xE9
#define findOpcode(_opcodeValue,offset)(*(_opcodeValue + offset) == 0XCC || *(_opcodeValue + offset) == 0x90 || *(_opcodeValue + offset) == 0x00)
#define relativeOpcode(_relativeValue) ((0xE0<=*(_relativeValue) &&  *(_relativeValue)<= 0xE3) || *(_relativeValue) == 0xE8 || *(_relativeValue)== 0xE9 || *(_relativeValue) == 0xEB)
#define jmpOpcode(_opcode,offset)((0x80<=*(_opcode+offset+1) &&  *(_opcode+offset+1)<= 0x8F) && *(_opcode+offset) == 0x0F) //condition jump
#define MAX_RELATIVE 32

struct _HOOKINFO
{
	uint64_t *_oldFunction; //Original Function Address
	uint64_t *_newFunction; //New Function Address 
	uint64_t *_hookFunction; //Hooked Function Address
	uint64_t _relativeValue[MAX_RELATIVE];
	uint8_t _relativeCount; 
};

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

struct _HOOKINFO _hookInfo;
_WriteFile _originalWriteFile = NULL;

int _initialize();
int _processArchitectureInfo();
LPWSTR _getFunctionAddress(LPWSTR _fAddress, int _arch);
int _getSize(unsigned char* _fAddress, int _control);
int _allocation(unsigned char* _fAddress, size_t _functionSize);
int _trambolin(unsigned char* _fAddress, int _arch, size_t _size, DWORD _protection);
int _getHookFunctionAddress(int _fAddress);

/*
TO DO :

- Add 64 bit support
- edit _getSize() function for 64 bit
*/

