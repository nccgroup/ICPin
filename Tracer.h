#pragma once
#include "common.h"
#include "memaccess.h"

#define MAX_NB_THREADS 200
#define BBL_BACKTRACE 80


// Everything static - cant afford singleton overhead
class tracer
{
private:
	enum TRACKTYPE {
		NOTCODE=0,
		TRACK,
		TRACKANDLOG,
		TRACK_LOG_RAISE
	};
	static vector<vector<ADDRINT>> trace; // one trace vector for each thread
	static UINT current[MAX_NB_THREADS];
	static map<ADDRINT, pair<ADDRINT, WIN::DWORD>> dynamicCodeAllocs;
	static std::tr1::unordered_map<ADDRINT, Gadget*> gadgets; // List of gadgets
	static VOID GetLastMemState();
public:
	static VOID track(THREADID, ADDRINT);
	static VOID trackdynamic(THREADID, CONTEXT*, ADDRINT, BOOL);
	static VOID Trace(TRACE, VOID*);
	static ADDRINT IsThisCode(ADDRINT);
	static VOID Instruction(INS, VOID*);
	static vector<ADDRINT> GetTrace(THREADID);
	static VOID addCodeRange(THREADID, ADDRINT, ADDRINT, WIN::DWORD);
	static VOID removeCodeRange(ADDRINT);
	static VOID UpdateCodeRangeProtect(ADDRINT, WIN::DWORD);
	static ADDRINT GetCurrentBBL(THREADID);
	static ADDRINT GetPreviousBBLAddress(THREADID, UINT);
	static VOID LogCode(BBL);
	static VOID RecordMemAccess(ADDRINT, ADDRINT, size_t, INT);
	static VOID print_results();
};