#pragma once

// Standard C
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
// C++
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <set>
#include <time.h>
#include <locale>
#include <algorithm>
// Pin
#include "pin.H"

// Memory access types
#define READ 0
#define WRITE 1
#define OTHER 2

typedef unsigned long DWORD;
namespace WIN {
#pragma once
#define _WINDOWS_H_PATH_ C:\Program Files (x86)\Windows Kits\10\Include\10.0.17134.0\um
#include <windows.h>
}

#define PAGE_ANYEXE (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)

#ifdef _WIN64
	#define REG_PC REG_RIP
	#define REG_SP REG_RSP
#else:
	#define REG_PC REG_EIP
	#define REG_SP REG_ESP
#endif

namespace Util {
	// Vars
	extern FILE *log;
	extern time_t tStart;
	extern string imageName;
	extern ADDRINT base, start, end, entry;
	// Funcs
	UINT64 READ_SIZE(ADDRINT, size_t);
	VOID loginit(string);
	VOID logend();
	VOID Log(BOOL, const char* fmt...);
	VOID startTimer();
	double queryElapsedTime(BOOL);
	string StrtoLower(string);
	VOID printContext(const CONTEXT*, UINT32);
}