#include "Header.h"


void main()
{
	_initialize();//you can give argument1:Function, argument2:DLL
	
	HANDLE hFile = CreateFile(L"NewFile.txt",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW||OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);

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

int _initialize()
{
	LPCSTR  lpProcName = "WriteFile";
	HMODULE _handle;

	_handle = LoadLibrary(TEXT("kernel32.dll"));
	if (_handle == NULL)
	{
		printf_s("Error : %d", GetLastError());
	}
	
	LPWSTR _functionAddress = NULL;
	_functionAddress = GetProcAddress(_handle, lpProcName); 
	
	int _architecture = 0;
	_architecture = _processArchitectureInfo();
	
	_hookInfo._oldFunction = _getFunctionAddress(_functionAddress,_architecture); //Get orjinal Function Address

	size_t _size = 0;
	int control = 0x1;
	_size = _getSize(_hookInfo._oldFunction, control); //control for relative address

	DWORD _protection = 0;
	_protection = _allocation(_hookInfo._oldFunction, _size);


	_trambolin(_hookInfo._oldFunction, _architecture, _size, _protection);

	_originalWriteFile = _hookInfo._newFunction;
	
}

int _processArchitectureInfo()
{
	wchar_t  lpFilename[MAX_PATH];

	HMODULE _module = GetModuleHandle(NULL);
	GetModuleFileNameW(_module, lpFilename, MAX_PATH);
	IMAGE_DOS_HEADER* _dosHeader = (IMAGE_DOS_HEADER*)_module;
	IMAGE_NT_HEADERS* _ntHeader = (IMAGE_NT_HEADERS*)(((char*)_dosHeader) + _dosHeader->e_lfanew);

	return _ntHeader->FileHeader.Machine;
}


LPWSTR _getFunctionAddress(LPWSTR _fAddress)
{
	uint64_t _functionAddress = (uint64_t)_fAddress;
	
	printf_s("Function Address : 0x%llX\n", _functionAddress);

#if defined(__x86_64__) || defined(_M_X64) 
	unsigned char* _getAddress = _functionAddress;
	unsigned char _getOffset[8];
	uint64_t _offset = 0x0;
    uint64_t *_realAddress = 0x0;
	int count = 0;

	memset(_getOffset, '\0', sizeof(char) * 8);

	for (int i = 0; i < 5; i++)
	{
		if (_getAddress[i] == 0xFF || _getAddress[i] == 0x25) // jmp and null
		{
			continue;
		}
		else
		{
			_getOffset[count] = *(_getAddress + i);
			count++;
		}
	}
	_offset = *(uint64_t*)_getOffset;
	_realAddress = _functionAddress + _offset + 0x6;
	printf_s("Real Function Address : 0x%llX\n", *_realAddress); // real adres : 0x7FFE12C94FD0 + 5D1E2

	return *_realAddress;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
	
	wchar_t* _getAddress = _functionAddress;

	__asm
	{
		pushad
		pushfd
		mov edi, esp
		xor eax, eax
		xor ebx, ebx
		mov eax, dword ptr[_getAddress]
		loop1:
		mov bx, word ptr[eax]
			add eax, 1
			cmp bx, JMPOPCODE//FF 25 jump opcode near jump 
			jnz loop1
			mov edx, [eax + 1]
			mov ecx, [edx]
			mov dword ptr[_getAddress], ecx
			mov esp, edi
			popfd
			popad

	}
	
	printf_s("Real Function Address : 0x%X\n", _getAddress);

	return _getAddress;
#endif
}

int _getSize(unsigned char* _fAddress, int _control)
{
	csh g_capstone;
	unsigned char* addr;
	cs_insn* insn;
	size_t j;
	
	unsigned char* _opcodeValue = NULL;
	unsigned char* _bytes;
	int size=0,inc=0;
	uint32_t* _getRel;
	uint32_t diff;

	_hookInfo._relativeCount = 0;


#if defined(__x86_64__) || defined(_M_X64) 
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &g_capstone) != CS_ERR_OK)
		return -1;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &g_capstone) != CS_ERR_OK)
		return -1;
#endif

	addr = _fAddress;
	size_t count = cs_disasm(g_capstone, addr, 0x10000, (uintptr_t)addr, 0, &insn); //64 bitde adres boyutundan dolayı patlıyor tekrar bak

	if (count > 0) 
	{
		for (j = 0; j < count; j++) 
		{
			_opcodeValue = insn[j].address;
			_bytes = &insn[j].bytes[0];
			size += insn[j].size;

			if (findOpcode(_opcodeValue, 0x0) && findOpcode(_opcodeValue, 0x1) && findOpcode(_opcodeValue, 0x2) && findOpcode(_opcodeValue, 0x3))
				break;
			else if (relativeOpcode(_bytes, 0x0) && insn[j].size >= 5) //call size 5
			{
				if (_control == 0x1) 
					_calculateRelativeAddress(&insn[j].op_str[2]);
				else 
				{
					diff = (_hookInfo._relativeValue[inc++] - insn[j].address - 0x5);
					*(uint32_t *)(_opcodeValue + 1) = diff;
				}
			}
			else if (jmpOpcode(_bytes, 0x0)) //jmp 6 size
			{ 
				if (_control == 0x1) 
					_calculateRelativeAddress(&insn[j].op_str[2]);
				else 
				{
					diff = (unsigned char*)(_hookInfo._relativeValue[inc++] - insn[j].address - 0x6);
					*(uint32_t*)(_opcodeValue + 2) = diff;
				}
			}
			else if (*_bytes == 0xFF && insn[j].size >= 5){//call 6 size
				if (_control == 0x1)
				{
					_getRel = &insn[j].bytes[0x2];
					_hookInfo._relativeValue[_hookInfo._relativeCount] = *_getRel;
					_hookInfo._relativeCount = _hookInfo._relativeCount + 1;
				}
				else
				{
					*(uint32_t*)(_opcodeValue + 2) = _hookInfo._relativeValue[inc++];
				}
			}
			if (_control == 0x0)
				printf("0x%"PRIx64":\t%s\t\t%s\t\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}
		cs_free(insn, count);
	}
	else
		printf("ERROR: Failed to disassemble given code!\n");

	printf_s("Function Size : %d\n", size);

	return size;
}

int _calculateRelativeAddress(uint32_t* _address)
{
	uint64_t _tmp;
	uint32_t _getRel;

	_tmp = _address;
	_getRel = strtol(_tmp, 0, 16);
	_hookInfo._relativeValue[_hookInfo._relativeCount] = _getRel;
	_hookInfo._relativeCount = _hookInfo._relativeCount + 1;
}

int _allocation(unsigned char* _fAddress, size_t _functionSize)
{
	unsigned char* _newFunctionAddress = _fAddress - _functionSize - 0x400;
	unsigned char* _newFunction = NULL;

	while (_newFunction == NULL)
	{
		_newFunction = VirtualAlloc(_newFunctionAddress, _functionSize + 0x20, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		_newFunctionAddress -= 0x1000; //1 page 4kb = 4096
	}

	memset(_newFunction,0x90,_functionSize+0x20);
	memcpy(_newFunction,_fAddress,_functionSize);

	_getSize(_newFunction, 0x0);

	DWORD _protection = 0;
	if (!VirtualProtect(_fAddress, _functionSize, PAGE_EXECUTE_READWRITE, &_protection))
	{
		printf_s("%d",GetLastError());
		VirtualFree(_newFunction, _functionSize + 0x20, MEM_RELEASE);
	}

	_hookInfo._newFunction = _newFunction;

	memset(_fAddress,0x90,_functionSize);


	return _protection;
}

int _trambolin(unsigned char* _fAddress, int _arch, size_t _size, DWORD _protection)
{
	if (_arch == 0x8664) //64
	{
		//mov rax, 64BIT_FUNCTION_ADDRESS
		//jmp rax
		*_fAddress = (unsigned char)0x48;//rax
		*(_fAddress + 1) = (unsigned char)0xB8;//mov
		*(long long int*)(_fAddress + 2) = (long long int)_hookWriteFile;
		*(unsigned short*)(_fAddress + 10) = 0xE0FF;


	}
	else //86
	{
		uint32_t _address = _getHookFunctionAddress(&_hookWriteFile,0x14C);
		int _JMPOffset = _fAddress - _address;
		_JMPOffset = -_JMPOffset;
		_JMPOffset = _JMPOffset - 0x5;
		*_fAddress = (unsigned char)0xE9;
		*((int*)(_fAddress + 1)) = _JMPOffset;

		VirtualProtect(_fAddress,_size,_protection,&_protection);

		_hookInfo._hookFunction = _address;
	}
	
}

int _getHookFunctionAddress(int _fAddress, int _arch) 
{
	unsigned char* _adres = _fAddress;
	unsigned char _getOffset[4];
	int count = 0;

	memset(_getOffset, '\0', sizeof(char) * 4);

	for (int i = 0; i < 5; i++)
	{
		if (_adres[i] == 0xE9 || _adres[i] == 0x00) // jmp and null
		{
			continue;
		}
		else
		{
			_getOffset[count] = *(_adres + i);
			count++;
		}
	}
	
	uint32_t _offset = *(uint32_t*)_getOffset;
	uint32_t _realAddress =  _fAddress + _offset + 0x5;

	return _realAddress;
}


BOOL WINAPI _hookWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	LPCVOID _msg = "ON WINDOWS 10 :)";

	int _size = (nNumberOfBytesToWrite + 0x40) * sizeof(char);
	const char * _hookData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,_size);
	int _hookDataLen = strlen(_msg);

	printf_s("Original Write File lpBuffer : %s \n", lpBuffer);

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
	
	HeapFree(GetProcessHeap(),0,_hookData);

	return result;
}