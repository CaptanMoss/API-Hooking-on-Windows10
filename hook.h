#pragma once

	//install capstone
#if defined(__x86_64__) || defined(_M_X64) 
#include "csinclude/capstone/capstone.h"
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#include "../csinclude/capstone/capstone.h"
#endif

#include <wtypes.h>

#define JMPOPCODE 0x25FF
#define CALLOPCODE 0xE8
#define CALLRETURN 0xC35D
#define CALLRETURN2 0xC25D
#define _JMP 0xE9
#define findOpcode(_opcodeValue,offset)(*(_opcodeValue + offset) == 0XCC || *(_opcodeValue + offset) == 0x90 || *(_opcodeValue + offset) == 0x00)
#define relativeOpcode(_relativeValue) ((0xE0<=*(_relativeValue) &&  *(_relativeValue)<= 0xE3) || *(_relativeValue) == 0xE8 || *(_relativeValue)== 0xE9 || *(_relativeValue) == 0xEB)
#define jmpOpcode(_opcode,offset)((0x80<=*(_opcode+offset+1) &&  *(_opcode+offset+1)<= 0x8F) && *(_opcode+offset) == 0x0F) //condition jump
#define MAX_RELATIVE 32

	struct _HOOKINFO
	{
		uint64_t* _oldFunction; //Original Function Address
		uint64_t* _newFunction; //New Function Address 
		uint64_t* _hookFunction; //Hooked Function Address
		uint64_t _relativeValue[MAX_RELATIVE];
		uint8_t _relativeCount;
	};


	struct _HOOKINFO _hookInfo;

	int _processArchitectureInfo();
	uint64_t _getFunctionAddress(DWORD _fAddress);
	int _getSize(unsigned char* _fAddress, int _control);
	int _allocation(unsigned char* _fAddress, size_t _functionSize, int _control);
	void _trambolin(unsigned char* _fAddress, unsigned char* _hookFuncAddres, int _arch, size_t _size, DWORD _protection);
	int _getHookFunctionAddress(int _fAddress);

