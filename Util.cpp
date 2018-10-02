#include "common.h"

namespace Util {
	// Vars
	FILE *log;
	time_t tStart;
	string imageName;
	ADDRINT base, start, end, entry;

	// This is quick (?)
	UINT64 __inline Util::READ_SIZE(ADDRINT ptr, size_t size)
	{
		size_t ret;
		switch (size) {
		case 1:
			ret = (*(CHAR*)ptr);
			break;
		case 2:
			ret = (*(unsigned short*)ptr);
			break;
		case 4:
			ret = (*(unsigned long*)ptr);
			break;
		case 8:
			ret = (*(UINT64*)ptr);
			break;
		default:
			break;
		}
		return ret;
	}

	VOID loginit(string filename)
	{
		log = fopen(filename.c_str(), "w");
	}

	VOID logend()
	{
		fflush(log);
		fclose(log);
	}

	VOID Log(BOOL now, const char *fmt ...)
	{
		va_list argptr;
		va_start(argptr, fmt);
		vfprintf(log, fmt, argptr);
		va_end(argptr);
		if (now) {
			fflush(log);
		}
	}

	VOID startTimer()
	{
		time(&tStart);
		return;
	}

	double queryElapsedTime(BOOL reset)
	{
		time_t tNow;
		time(&tNow);
		double elapsed = difftime(tNow, tStart);
		if (reset) {
			startTimer();
		}
		return elapsed;
	}

	string StrtoLower(string s)
	{
		string ret(s);
		for (int i = 0; s[i]; i++) {
			ret[i] = tolower(s[i]);
		}
		return ret;
	}

#if _WIN64
	VOID printContext(const CONTEXT *ctx, UINT32 c)
	{
		Log(TRUE, "RAX = %p\tRBX = %p\tRCX = %p\nRDX = %p\tRSI = %p\tRDI = %p\nRBP = %p\tRSP = %p\tRIP = %p\n",
			PIN_GetContextReg(ctx, REG_RAX),
			PIN_GetContextReg(ctx, REG_RBX),
			PIN_GetContextReg(ctx, REG_RCX),
			PIN_GetContextReg(ctx, REG_RDX),
			PIN_GetContextReg(ctx, REG_RSI),
			PIN_GetContextReg(ctx, REG_RDI),
			PIN_GetContextReg(ctx, REG_RBP),
			PIN_GetContextReg(ctx, REG_RSP),
			PIN_GetContextReg(ctx, REG_RIP));
		// TODO: use the safe copy API
		//UINT count = ((c == -1) ? ((PIN_GetContextReg(ctx, REG_RBP)-PIN_GetContextReg(ctx, REG_RSP))/sizeof(ADDRINT))+1 : c);
		//ADDRINT *ptr = (ADDRINT*)PIN_GetContextReg(ctx, REG_RSP);
		//for (UINT32 i = 0; i < count; i++) {
		//	Log(TRUE, "[%08x]: %08x\n", ptr, *ptr);
		//	ptr++;
		//}
	}
#else
	VOID printContext(const CONTEXT *ctx, UINT32 c)
	{
		Log(TRUE, "EAX = %08x\tEBX = %08x\tECX = %08x\nEDX = %08x\tESI = %08x\tEDI = %08x\nEBP = %08x\tESP = %08x\tEIP = %08x\n",
			PIN_GetContextReg(ctx, REG_EAX),
			PIN_GetContextReg(ctx, REG_EBX),
			PIN_GetContextReg(ctx, REG_ECX),
			PIN_GetContextReg(ctx, REG_EDX),
			PIN_GetContextReg(ctx, REG_ESI),
			PIN_GetContextReg(ctx, REG_EDI),
			PIN_GetContextReg(ctx, REG_EBP),
			PIN_GetContextReg(ctx, REG_ESP),
			PIN_GetContextReg(ctx, REG_EIP));
		// TODO: use the safe copy API
		UINT count = ((c == -1) ? ((PIN_GetContextReg(ctx, REG_EBP) - PIN_GetContextReg(ctx, REG_ESP)) / sizeof(VOID*)) + 1 : c);
		ADDRINT *ptr = (ADDRINT*)PIN_GetContextReg(ctx, REG_ESP);
		for (UINT32 i = 0; i < count; i++) {
			Log(TRUE, "[%08x]: %08x\n", ptr, *ptr);
			ptr++;
		}
	}
#endif
}