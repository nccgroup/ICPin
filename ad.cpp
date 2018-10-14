#include "ad.h"

// class statics
std::tr1::unordered_set<ad_hook> ad_hook::ad_functions; // List of watched potential aad functions

// routine hook ad contructor
ad_hook::ad_hook(enum TYPE t, string n, string d, AFUNPTR h) : type(t), name(n), hook(h), genre(ROUTINE)
{
	// Convert dll string to lower case so hash function works as intended
	dll = Util::StrtoLower(d);
}

ad_hook::ad_hook(enum TYPE t, string n, string d, AFUNPTR h, AFUNPTR p) : type(t), name(n), hook(h), post(p), genre(ROUTINE)
{
	// Convert dll string to lower case so hash function works as intended
	dll = Util::StrtoLower(d);
}

// instruction hook ad constructor
ad_hook::ad_hook(enum TYPE t, string n, AFUNPTR h) : type(t), name(n), hook(h), dll(string("nope.dll")), genre(INSTRUCTION) {}

//#define EMULATE_WINDOWS_BOTCHED_LONG_INT
VOID ad_hook::HookInterrupt(ad_hook *adf, CONTEXT *ctxt, THREADID tid)
{
	UINT8 op, intcode=3; // default to int 3
	EXCEPTION_INFO exceptInfo;
	ADDRINT ip = PIN_GetContextReg(ctxt, REG_PC);

	adf->UpdateTrace(tracer::GetTrace(tid));
	// Fire a replacement interrupt to the OS if long int
	PIN_SafeCopy(&op, (VOID*)ip, sizeof(op));
	if (op == 0xCD) {
		PIN_SafeCopy(&intcode, (VOID*)(ip + 1), sizeof(op));
		if (intcode == 0x3 || intcode == 0x2d) {
			// Log and trace
			Util::Log(TRUE, "[INT] Using software interrupt (OP: #%x, INT #%x) at %p\n", op, intcode, ip);
			PIN_InitExceptionInfo(&exceptInfo, EXCEPTCODE_DBG_BREAKPOINT_TRAP, ip);
#ifndef EMULATE_WINDOWS_BOTCHED_LONG_INT
	// Default: NOT emulating windows botched behavior
	#ifdef _WIN64
			PIN_SetContextReg(ctxt, REG_PC, ip + 3); // Context points after the interrupt instruction
	#else
			PIN_SetContextReg(ctxt, REG_PC, ip + 2); // Context points after the interrupt instruction
	#endif
#else
	// EMULATING windows botched behavior
	#ifdef _WIN64
			PIN_SetContextReg(ctxt, REG_PC, ip + 2); // Context points in the middle of the instruction
	#else
			PIN_SetContextReg(ctxt, REG_PC, ip + 1); // Context points in the middle of the instruction
	#endif
#endif
			PIN_RaiseException(ctxt, tid, &exceptInfo);
		}
	}
	// Log and trace
	Util::Log(TRUE, "[INTERRUPT] Using software interrupt (OP: #%x, INT #%x) at %p\n", op, intcode, ip);
	return;
}


VOID ad_hook::HookVirtualAlloc(ad_hook *adf, THREADID tid, WIN::SIZE_T dwSize, WIN::DWORD protect)
{
	Util::Log(TRUE, "[VirtualAlloc] TID %#x call at bbl %p (protect %08x)\n", tid, tracer::GetCurrentBBL(tid), protect);
	// Keep a per-thread ref to the call in order to link with post
	adf->allocs[tid].first = dwSize;
	adf->allocs[tid].second = protect;
}

VOID ad_hook::PostVirtualAlloc(ad_hook *adf, THREADID tid, ADDRINT mem, ADDRINT ret)
{
	// Check call success and return address belongs to us
	if (mem && tracer::IsThisCode(ret)) {
		// Is there a ongoing call on that thread?
		auto &alloc = adf->allocs.find(tid);
		if (alloc != adf->allocs.end()) {
			// Update trace only if mem is GUARD or EXE
			if (alloc->second.second&(PAGE_GUARD|PAGE_ANYEXE)) {
				adf->UpdateTrace(tracer::GetTrace(tid));
			}
			// Watch new code range
			tracer::addCodeRange(tid, mem, mem + alloc->second.first, alloc->second.second);
		}
	}
	// Clear the record
	adf->allocs.erase(tid);
}

VOID ad_hook::HookVirtualProtect(ad_hook *adf, THREADID tid, ADDRINT address, WIN::DWORD protect)
{
	if (tracer::IsThisCode(tracer::GetCurrentBBL(tid)) && protect&(PAGE_GUARD|PAGE_ANYEXE)) {
		Util::Log(TRUE, "[VirtualProtect] TID %#x call (protect %08x)\n", tid, protect);
		// Only record trace if the protection is interesting
		adf->UpdateTrace(tracer::GetTrace(tid));
	}
	tracer::UpdateCodeRangeProtect(address, protect);
	return;
}

VOID ad_hook::HookVirtualFree(ad_hook *adf, THREADID tid, WIN::LPVOID lpAddress)
{
	//Util::Log(TRUE, "[VirtualFree] & = %08x\n", lpAddress);
	if (lpAddress) {
		tracer::removeCodeRange((ADDRINT)lpAddress);
	}
}

// This runs post function
VOID ad_hook::HookNtQueryObject(ad_hook *adf, THREADID tid, ADDRINT handle, ADDRINT type, ADDRINT mem, ADDRINT size)
{
#define ObjectAllInformation 3
	if (type == ObjectAllInformation && size) {
		Util::Log(TRUE, "[ANTIDEBUG] Attempting to detect debugger via NtQueryObject (%#p,%#p,%#p)\n", type, mem, size);
		adf->UpdateTrace(tracer::GetTrace(tid));
	}
	return;
}

VOID ad_hook::HookCloseHandle(ad_hook *adf, THREADID tid, ADDRINT handle)
{
// TODO: Less specific check
#define BADHANDLE 0x12345

	if (handle == BADHANDLE) {
		adf->UpdateTrace(tracer::GetTrace(tid));
		Util::Log(TRUE, "[ANTIDEBUG] Attempting to close invalid handle\n");
	}
	else {
		// Util::Log(TRUE, "CloseHandle(%x)\n", handle);
	}
}

VOID ad_hook::UpdateTrace(vector<ADDRINT>& newtrace)
{
	ADDRINT bblip = newtrace[BBL_BACKTRACE - 1];
	//Util::Log(TRUE, "Hit at BB %#p\n", bblip);
	auto& backtrace = backtraces[bblip];
	// Check that we do not already have a trace
	if (backtrace.empty()) {
		backtrace = newtrace;
	}
	else {
		// TODO: more analysis on different traces
	}
}

// Static hook
VOID ad_hook::HookNtQueryInformationProcess(ad_hook *adf, THREADID tid, UINT32 handle, UINT32 flag)
{
#define ProcessDebugObjectHandle 0x1e
#define ProcessDebugFlags 0x1f
#define ProcessDebugPort 0x7

	if (flag == ProcessDebugObjectHandle) {
		adf->UpdateTrace(tracer::GetTrace(tid));
		Util::Log(TRUE, "[ANTIDEBUG] Attempting to query process debug object\n");
	}
	else if (flag == ProcessDebugFlags) {
		adf->UpdateTrace(tracer::GetTrace(tid));
		Util::Log(TRUE, "[ANTIDEBUG] Attempting to query process debug flags\n");
	}
	else if (flag == ProcessDebugPort) {
		adf->UpdateTrace(tracer::GetTrace(tid));
		Util::Log(TRUE, "[ANTIDEBUG] Attempting to query process debug port\n");
	}
	else {
		//Util::Log(TRUE, "NtQueryInformationProcess Flag = %x\n", flag);
	}
	return;
}

BOOL ad_hook::UpdateWatchedAD(string fnName, string imageName, ADDRINT address)
{
	auto& it = ad_functions.find(ad_hook(UNDEFINED, fnName, imageName, NULL));
	if (it != ad_functions.end()) {
		RTN routine = RTN_FindByAddress(address);
		if (RTN_Valid(routine)) {
			it->instrumentRoutine(routine);
			return TRUE;
		}
		else {
			Util::Log(TRUE, "INVALID RTN\n");
		}
	}
	return FALSE;
}

VOID ad_hook::printAllAdBacktraces()
{
	for (auto& ad : ad_functions) {
		ad.PrintTrace(FALSE);
	}
	return;
}

VOID ad_hook::instrumentRoutine(RTN rtn) const
{
	RTN_Open(rtn);
	switch (type) {
	case CLOSEHANDLE:
		RTN_InsertCall(rtn, IPOINT_BEFORE, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		break;
	case NTQIP:
		RTN_InsertCall(rtn, IPOINT_BEFORE, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
		break;
	case NTQOB:
		RTN_InsertCall(rtn, IPOINT_AFTER, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END);
		break;
	case UEXCEPT:
		RTN_InsertCall(rtn, IPOINT_BEFORE, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_REG_VALUE, REG_SP,
			IARG_END);
		break;
	case VMALLOC:
		RTN_InsertCall(rtn, IPOINT_BEFORE, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, post,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_RETURN_IP,
			IARG_END);
		break;
	case VMFREE:
		RTN_InsertCall(rtn, IPOINT_BEFORE, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		break;
	case VMPROT:
		RTN_InsertCall(rtn, IPOINT_BEFORE, hook,
			IARG_PTR, this,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_END);
		break;
	}
	RTN_Close(rtn);
	Util::Log(TRUE, "[HOOK]  - %s\n", this->name.c_str());
	return;
}

VOID ad_hook::instrumentInstruction(INS ins, VOID *v)
{
	if (INS_IsInterrupt(ins)) {
		if (tracer::IsThisCode(INS_Address(ins))) {
			// Util::Log(FALSE, "[%#p] int %x\n", INS_Address(ins), INS_OperandImmediate(ins, 0));
			tr1::unordered_set<ad_hook>::iterator &ref = ad_functions.find(ad_hook(INTERRUPT, string("interrupts"), (AFUNPTR)HookInterrupt));
			if (ref != ad_functions.end()) {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HookInterrupt,
					IARG_PTR, &*ref,
					IARG_CONTEXT,
					IARG_THREAD_ID,
					IARG_END);
			}
		}
	}
	// else if...
	return;
}

VOID ad_hook::setup()
{
	// Routine based
	ad_functions.insert(ad_hook(CLOSEHANDLE, string("CloseHandle"), string("kernelbase.dll"), (AFUNPTR)HookCloseHandle));
	ad_functions.insert(ad_hook(NTQIP, string("NtQueryInformationProcess"), string("ntdll.dll"), (AFUNPTR)HookNtQueryInformationProcess));
	ad_functions.insert(ad_hook(NTQOB, string("NtQueryObject"), string("ntdll.dll"), (AFUNPTR)HookNtQueryObject));
	ad_functions.insert(ad_hook(VMALLOC, string("VirtualAlloc"), string("kernelbase.dll"), (AFUNPTR)HookVirtualAlloc, (AFUNPTR)PostVirtualAlloc));
	ad_functions.insert(ad_hook(VMFREE, string("VirtualFree"), string("kernelbase.dll"), (AFUNPTR)HookVirtualFree));
	ad_functions.insert(ad_hook(VMPROT, string("VirtualProtect"), string("kernelbase.dll"), (AFUNPTR)HookVirtualProtect));
	// ADD MORE HERE
	// Instruction based
	ad_functions.insert(ad_hook(INTERRUPT, string("interrupts"), (AFUNPTR)HookInterrupt));
	INS_AddInstrumentFunction(instrumentInstruction, 0);
	return;
}

VOID ad_hook::PrintTrace(BOOL forward) const
{
	Util::Log(FALSE, "BACKTRACES for %s\n", name.c_str());
	for (auto& trace : backtraces) {
		Util::Log(FALSE, "[%#p] : ", trace.first);
		for (auto addr : trace.second) {
			Util::Log(FALSE, "-> %#p ", addr);
		}
		Util::Log(FALSE, "\n--------\n");
	}
	Util::Log(TRUE, "----------------------\n");
	return;
}
