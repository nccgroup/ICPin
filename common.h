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

namespace WIN {
#define _WINDOWS_H_PATH_ C:\Program Files (x86)\Windows Kits\8.1\Include\um
#include <windows.h>
#define	EXCEPTION_BREAKPOINT 0x80000003
#define	STATUS_GUARD_PAGE_VIOLATION 0x80000001
#define EXCEPTION_ACCESS_VIOLATION 0xc0000005
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