#include "Tracer.h"

vector<vector<ADDRINT>> tracer::trace(MAX_NB_THREADS, vector<ADDRINT>(BBL_BACKTRACE));
map<ADDRINT, pair<ADDRINT, WIN::DWORD>> tracer::dynamicCodeAllocs;
UINT tracer::current[MAX_NB_THREADS] = { 0 };
std::tr1::unordered_map<ADDRINT, Gadget*> tracer::gadgets;

// This must be fast
// TODO: use trace buffer ? https://software.intel.com/sites/landingpage/pintool/docs/65163/Pin/html/index.html#Buffering
VOID tracer::track(THREADID tid, ADDRINT addr)
{
	if (tid < MAX_NB_THREADS) {
		trace[tid][current[tid]] = addr;
		// current[tid] should point at the next 'free' bbl address
		// so the insert call in GetTrace is straightfoward [)
		if (++current[tid] >= BBL_BACKTRACE) {
			current[tid] = 0;
		}
	}
	return;
}

VOID tracer::trackdynamic(THREADID tid, CONTEXT *ctxt, ADDRINT sp, BOOL guard)
{
	EXCEPTION_INFO exceptInfo;
	ADDRINT ip;

	// Just print backtrace on how we got here
	auto& trace = GetTrace(tid);
	Util::Log(TRUE, "[DYNAMIC_CODE] Thread %p backtrace: ", tid);
	for (auto addr : trace) {
		Util::Log(FALSE, "-> %#p ", addr);
	}
	Util::Log(FALSE, "\n--------\n");

	// Rethrow the guard page
	if (guard) {
		// Capture exception to-be address
		ip = PIN_GetContextReg(ctxt, REG_PC);
		// Check the page for guard flag
		Util::Log(TRUE, "[DYNAMIC_CODE] PAGE_GUARD AT %p\n", ip);
		// Initialize a PAGE_GUARD_EXCEPTION
		PIN_InitAccessFaultInfo(&exceptInfo, EXCEPTCODE_ACCESS_WINDOWS_GUARD_PAGE, ip, ip, FAULTY_ACCESS_EXECUTE);
		//PIN_InitWindowsExceptionInfo(&exceptInfo, STATUS_GUARD_PAGE_VIOLATION, ip, 0, NULL);
		PIN_RaiseException(ctxt, tid, &exceptInfo);
	}
	return;
}

// Instrument all the basic blocks for tracing
VOID tracer::LogCode(BBL bbl)
{
	INS ins = BBL_InsHead(bbl);
	for (UINT i=0; i<BBL_NumIns(bbl); i++) {
		Util::Log(TRUE, "[DYNAMIC_CODE] %p: %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
		ins = INS_Next(ins);
	}
	return;
}

// Instrument all the basic blocks for tracing
VOID tracer::Trace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/*BBL_InsertIfCall(bbl, IPOINT_BEFORE, (AFUNPTR)IsThisCode,
			IARG_ADDRINT, BBL_Address(bbl),
			IARG_END);*/
		ADDRINT tracking = IsThisCode(BBL_Address(bbl));
		if (tracking != NOTCODE) {
			BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)track,
				IARG_THREAD_ID,
				IARG_PTR, BBL_Address(bbl),
				IARG_END);
			if (tracking >= TRACKANDLOG) {
				// Log the dynamic code found
				LogCode(bbl);
				// This might also need to raise the page guard exception
				BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)trackdynamic,
					IARG_THREAD_ID,
					IARG_CONTEXT,
					IARG_REG_VALUE, REG_SP,
					IARG_BOOL, tracking==TRACK_LOG_RAISE,
					IARG_END);
			}
		}
	}
}

// TODO: Could this be made faster with PIN_FAST_ANALYSIS_CALL?
ADDRINT tracer::IsThisCode(ADDRINT addr)
{
	if (addr) {
		// This address belongs to watched binary's .text
		if ((addr >= Util::start) && (addr < Util::end)) {
			return TRACK;
		}
		auto &it = dynamicCodeAllocs.upper_bound(addr);
		if (it != dynamicCodeAllocs.begin()) {
			it--;
			// Check upper bound
			if (addr < it->second.first) {
				if (it->second.second&PAGE_GUARD) {
					return TRACK_LOG_RAISE;
				}
				if (it->second.second&PAGE_ANYEXE) {
					return TRACKANDLOG;
				}
			}
		}
	}
	return NOTCODE;
}

VOID tracer::Instruction(INS ins, VOID *v)
{
	ADDRINT addr = INS_Address(ins);
	// Only intrument our binary of interest
	if (IsThisCode(addr) && !INS_IsCall(ins)) {
		// This intruction reads and is not a jump (ignore .text jump tables)
		// TODO: Insert callback AFTER write
		if (INS_IsMemoryWrite(ins)) {
			INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IsThisCode,
				IARG_MEMORYWRITE_EA,
				IARG_END);
			INS_InsertThenPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemAccess,
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE,
				IARG_UINT32, WRITE,
				IARG_END);
		}
		// Must be mutually exclusive! treat read+write as a write
		else if (INS_IsMemoryRead(ins) && !INS_IsIndirectBranchOrCall(ins)) {
			// Insert callback BEFORE READ
			INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)IsThisCode,
				IARG_MEMORYREAD_EA,
				IARG_END);
			INS_InsertThenPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemAccess,
				IARG_INST_PTR,
				IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE,
				IARG_UINT32, READ,
				IARG_END);
		}
	}
}

vector<ADDRINT> tracer::GetTrace(THREADID tid)
{
	const vector<ADDRINT>::iterator& it = trace[tid].begin()+current[tid];
	//Util::Log(TRUE, "Trace requested. current[tid] is %#x. hit bbl is %#p\n", current[tid], trace[tid][current[tid]]);
	vector<ADDRINT> v = vector<ADDRINT>(it, trace[tid].end());
	v.insert(v.end(), trace[tid].begin(), it);
	return v;
}

// Returns the current BBL address
ADDRINT tracer::GetCurrentBBL(THREADID tid)
{
	return current[tid]==0 ? trace[tid][BBL_BACKTRACE-1] : trace[tid][current[tid]-1];
}

// For current, nb = 1, for previous nb == 2,  etc.
ADDRINT tracer::GetPreviousBBLAddress(THREADID tid, UINT nb)
{
	return current[tid] >= nb ? trace[tid][current[tid] - nb] : trace[tid][BBL_BACKTRACE - nb];
}

VOID tracer::addCodeRange(THREADID tid, ADDRINT start, ADDRINT end, WIN::DWORD protect)
{
	dynamicCodeAllocs.insert(pair<ADDRINT, pair<ADDRINT, WIN::DWORD>>(start, pair<ADDRINT, WIN::DWORD>(end, protect)));
	//Util::Log(TRUE, "[DYNAMIC_CODE] added watched range: %08x-%08x (%08x) \n", start, end, protect);
	Util::Log(TRUE, "[DYNAMIC_CODE] allocation backtrace: ");
	auto& trace = GetTrace(tid);
	for (auto addr : trace) {
		Util::Log(FALSE, "-> %p ", addr);
	}
	Util::Log(FALSE, "\n--------\n");
	Util::Log(TRUE, "[LIST] List of dynamic code allocs:\n");
	for (auto &range : dynamicCodeAllocs) {
		Util::Log(TRUE, "%p-%p (%08x)\n", range.first, range.second.first, range.second.second);
	}
	Util::Log(TRUE, "[ENDLIST]\n");
	return;
}

VOID tracer::removeCodeRange(ADDRINT start)
{
	if (dynamicCodeAllocs.erase(start)) {
		Util::Log(TRUE, "[DYNAMIC_CODE] Memory range freed\n");
		Util::Log(TRUE, "[LIST] List of dynamic code allocs:\n");
		for (auto &range : dynamicCodeAllocs) {
			Util::Log(TRUE, "%08x-%08x (%08x)\n", range.first, range.second.first, range.second.second);
		}
		Util::Log(TRUE, "[ENDLIST]\n");
	}
	return;
}

VOID tracer::UpdateCodeRangeProtect(ADDRINT address, WIN::DWORD protect)
{
	auto &it = dynamicCodeAllocs.find(address);
	//Util::Log(TRUE, "[DYNAMIC_CODE] range protection [%08x] %08x -> %08x\n", address, dynamicCodeAllocs[address].second, protect);
	if (it != dynamicCodeAllocs.end()) {
		dynamicCodeAllocs[address].second = protect;
	}
}

// Last pass to get final writes
VOID tracer::GetLastMemState()
{
	UINT64 val = 0;
	for (auto& g : gadgets) {
		if (g.second->type == WRITE) {
			WriteGadget *wg = static_cast<WriteGadget*>(g.second);
			for (auto& p : wg->offset_values) {
				PIN_SafeCopy(&val, (VOID*)p.first, wg->len);
				wg->update_offset_values(p.first, val);
			}
		}
	}
}

// Record a memory read or write on .text
VOID tracer::RecordMemAccess(ADDRINT ip, ADDRINT addr, size_t size, INT type)
{
	UINT64 val = 0;
	// Need to create new gadget?
	auto& it = gadgets.find(ip);
	if (it == gadgets.end()) {
		if (type == READ) {
			ReadGadget *rg = new ReadGadget(type, ip, addr, addr + size);
			gadgets.insert(pair<ADDRINT, Gadget*>(ip, rg));
		}
		else {
			// Write gadget
			PIN_SafeCopy(&val, (VOID*)addr, size);
			WriteGadget *wg = new WriteGadget(type, ip, addr, val, size);
			gadgets.insert(pair<ADDRINT, Gadget*>(ip, wg));
		}
		Gadget::current++;
	}
	else {
		// Insertion failed, existing gadget -> update offsets and values
		if (type == READ) {
			ReadGadget *rg = static_cast<ReadGadget*>(it->second);
			rg->update_range(addr, addr + size);
		}
		else {
			// Write gadget
			WriteGadget *wg = static_cast<WriteGadget*>(it->second);
			PIN_SafeCopy(&val, (VOID*)addr, size);
			wg->update_offset_values(addr, val);
		}
	}
	return;
}

VOID tracer::print_results()
{
	// Print runtime
	Util::Log(FALSE, "TIME: Running instrumented took %.2lf seconds\n", Util::queryElapsedTime(TRUE));
	// First get the last writes
	GetLastMemState();
	// Sorting method: first seen
	struct FirstSeenComp
	{
		bool operator()(const Gadget* a, const Gadget* b) const {
			if (a->firstSeen < b->firstSeen) {
				return true;
			}
			return false;
		}
	};
	// Sort the gadgets by first seen
	std::set<Gadget*, FirstSeenComp> ordered;
	for (auto& p : gadgets) {
		ordered.insert(p.second);
	}
	Util::Log(FALSE, "GADGET LIST ------------------------------ \n");
	for (auto& p : ordered) {
		p->print();
	}
	Util::Log(TRUE, "Total: %lu gadgets\n", gadgets.size()); // this will flush
}
