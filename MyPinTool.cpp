#include "MyPinTool.h"

KNOB<string> knob_imageName(KNOB_MODE_WRITEONCE, "pintool", "i", "", "Image name (defaults to main exe");

VOID Fini(INT32 code, VOID *v)
{
	// Print mem accesses
	tracer::print_results();
	// Print anti-debug gadgets backtraces
	ad_hook::printAllAdBacktraces();
	Util::Log(FALSE, "#DONE (%x)\n", code);
	Util::logend();
}

INT32 Usage()
{
	PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

VOID Image(IMG img, VOID *v)
{
	// Full binary path
	string imagePath = IMG_Name(img);
	// Get the image name
	string imageName = imagePath.substr(IMG_Name(img).rfind("\\") + 1);
	Util::Log(TRUE, "[LOAD] %s [%p - %p]\n", imagePath.c_str(), IMG_LowAddress(img), IMG_HighAddress(img));
	if (knob_imageName.Value().empty() && IMG_IsMainExecutable(img)
		|| (Util::StrtoLower(knob_imageName.Value()) == Util::StrtoLower(imageName))) {
		// TODO: HANDLE CODE RUN FROM RDATA AND OTHER SECTIONS
		// Get the .text section bounds
		SEC section = IMG_SecHead(img);
		do {
			if (SEC_Name(section) == string(".text")) {
				Util::base = IMG_LowAddress(img);
				Util::start = SEC_Address(section);
				Util::end = Util::start + SEC_Size(section);
				Util::entry = IMG_Entry(img);
				Util::Log(TRUE, "[TRACKER] Watching %s [%p - %p], entry at %08x\n", imageName.c_str(), Util::start, Util::end, Util::entry);
				break;
			}
			section = SEC_Next(section);
		} while (section != SEC_Invalid());
		// TODO: handle multiple ranges
		Util::imageName = imageName;
	}
	// Walk through the symbols in the symbol table.
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
		string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
		// If it is a watched symbol, update object with address
		ad_hook::UpdateWatchedAD(undFuncName, imageName, IMG_LowAddress(img) + SYM_Value(sym));
	}
}

#define MAX_DEBUG_LEN 1024
VOID exhandler(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
	char *debugstr=NULL;
	vector<ADDRINT> trace;

	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION) {
		switch (info) {
		case 0xe0434352:
			break;
		case 0x40010006:
			debugstr = (*(char**)(PIN_GetContextReg(from, REG_ESP) + 0x18));
			if (debugstr[0] != '%') {
				Util::Log(TRUE, "[DEBUG] %s", debugstr);
			}
			break;
		case 0x4001000a:
			// TODO: Print unicode debug output
			break;
		case EXCEPTION_BREAKPOINT:
		case STATUS_GUARD_PAGE_VIOLATION:
			Util::Log(TRUE, "[EXCEPTION] code: %#x\tip: %#p -> %#p\n", info, PIN_GetContextReg(from, REG_EIP), PIN_GetContextReg(to, REG_EIP));
			break;
		case EXCEPTION_ACCESS_VIOLATION:
			Util::Log(TRUE, "[EXCEPTION] code: %#x\tip: %#p -> %#p\n", info, PIN_GetContextReg(from, REG_EIP), PIN_GetContextReg(to, REG_EIP));
			Util::printContext(from, 40);
			trace = tracer::GetTrace(threadIndex);
			Util::Log(TRUE, "[%#x] ", threadIndex);
			for (auto &addr : trace) {
				Util::Log(TRUE, "%08x ", addr);
			}
			Util::Log(TRUE, "\n");
			//Fini(EXCEPTION_ACCESS_VIOLATION, NULL);
			break;
		default:
			Util::printContext(from, 0);
			break;
		}
	}
	return;
}

EXCEPT_HANDLING_RESULT internalException(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	Util::Log(TRUE, "[PINBUG] It was at this moment that pintool knew - %s\n", pExceptInfo->ToString().c_str());
	Fini(pExceptInfo->m_exceptCode, v);
	return EHR_UNHANDLED;
}

VOID AppStartCallback(VOID *v)
{
	Util::Log(FALSE, "[TIME] Initial instrumentation took %f seconds\n", Util::queryElapsedTime(TRUE));
}

int main(int argc, char *argv[])
{
	// Time accounting
	Util::startTimer();
	// Initialize symbol processing
	PIN_InitSymbols();
	// Pin init
	if (PIN_Init(argc, argv)) {
		return Usage();
	}
	// Setup the list of watched functions and instructions
	ad_hook::setup();
	// Open trace file
	Util::loginit("pinatrace.out");
	// Instrumentation for each image load
	IMG_AddInstrumentFunction(Image, 0);
	// Start tracer
	TRACE_AddInstrumentFunction(tracer::Trace, 0);
	INS_AddInstrumentFunction(tracer::Instruction, 0);
	// Register callback for pintool internal exception
	PIN_AddInternalExceptionHandler(internalException, NULL);
	// Register callback for intrumented binary exception
	PIN_AddContextChangeFunction(exhandler, 0);
	// Register function to be called at the end of all things
	PIN_AddFiniFunction(Fini, 0);
	PIN_AddApplicationStartFunction(AppStartCallback, NULL);
	// Never returns
	PIN_StartProgram();
	// Nope
	return 0;
}
