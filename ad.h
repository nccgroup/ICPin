#pragma once
#include "common.h"
#include "Tracer.h"

class ad_hook
{
	friend struct hash<ad_hook>;
private:
	enum GENRE {
		ROUTINE,
		INSTRUCTION
	};
	enum TYPE {
		UNDEFINED,
		CLOSEHANDLE,
		NTQIP,
		INTERRUPT,
		NTQOB,
		UEXCEPT,
		VMALLOC,
		VMFREE,
		VMPROT
	};
	GENRE genre;
	TYPE type;
	string name;
	string dll;
	// For instrumenting
	AFUNPTR hook;
	AFUNPTR post;
	UINT nbArgs;
	// Tracking
	tr1::unordered_map<ADDRINT,vector<ADDRINT>> backtraces;
	vector<ADDRINT> forwardtrace;
	tr1::unordered_map<THREADID, pair<WIN::SIZE_T, WIN::DWORD>> allocs;
	// List of all watched aad functions
	static std::tr1::unordered_set<ad_hook> ad_functions;
	VOID ad_hook::UpdateTrace(vector<ADDRINT>& newtrace);
public:
	// Constructor
	ad_hook(enum TYPE, string, string, AFUNPTR);
	ad_hook(enum TYPE, string, string, AFUNPTR, AFUNPTR);
	ad_hook(enum TYPE, string, AFUNPTR);
	// Members
	VOID instrumentRoutine(RTN) const;
	VOID PrintTrace(BOOL) const;
	// Statics
	static VOID setup();
	static BOOL UpdateWatchedAD(string, string, ADDRINT);
	static VOID printAllAdBacktraces();
	static VOID instrumentInstruction(INS, VOID*);
	// Hooks (have to be static)
	static VOID HookCloseHandle(ad_hook*, THREADID, ADDRINT);
	static VOID HookNtQueryInformationProcess(ad_hook*, THREADID, UINT32, UINT32);
	static VOID HookInterrupt(ad_hook*, CONTEXT*, THREADID);
	static VOID HookNtQueryObject(ad_hook*, THREADID, ADDRINT, ADDRINT, ADDRINT, ADDRINT);
	static VOID HookVirtualAlloc(ad_hook*, THREADID, WIN::SIZE_T, WIN::DWORD);
	static VOID HookVirtualProtect(ad_hook*, THREADID, ADDRINT, WIN::DWORD);
	static VOID HookVirtualFree(ad_hook*, THREADID, WIN::LPVOID);
	static VOID PostVirtualAlloc(ad_hook*, THREADID, ADDRINT, ADDRINT);
	// Equal operator for set
	bool operator==(const ad_hook &other) const {
		return type == other.type
			|| (name==other.name && dll==other.dll);
	}
};
// Hash functor for set
template <>
struct hash<ad_hook> {
	std::size_t operator()(const ad_hook& k) const {
		return (hash<string>()(k.name) ^ hash<string>()(k.dll));
	}
};