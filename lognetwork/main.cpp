#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#include "dbg.h"
#include "hookstuff.h"
#include "packet.h"

PVOID protVectoredHandler;

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);

VOID MakeConsole(VOID)
{
	FILE *stream;

	AllocConsole();
	freopen_s(&stream, "CONIN$","rb",stdin);
	freopen_s(&stream, "CONOUT$","wb",stdout);
	freopen_s(&stream, "CONOUT$","wb",stderr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{


	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		MakeConsole();
		setup_all_hook();
		protVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
	}
	return TRUE;
}

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		return EXCEPTION_CONTINUE_EXECUTION;
	//dbg_msg("Exception Code : %08X ; EIP : %08X\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ContextRecord->Eip);
	return EXCEPTION_CONTINUE_SEARCH;
}