#include "detection_routines.h"

bool Check_IsDebuggerPresent()
{
	//https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-isdebuggerpresent
	return IsDebuggerPresent();
}

bool Check_IsRemoteDebuggerPresent()
{
	//https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-checkremotedebuggerpresent
	BOOL bDebuggerPresent;
	return (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) &&
		TRUE == bDebuggerPresent);
}


bool Check_NtQueryIP_ProcessDebugPort()
{
	//https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugport
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			DWORD_PTR dwProcessDebugPort;
			DWORD dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				PROCESSINFOCLASS::ProcessDebugPort,
				&dwProcessDebugPort,
				sizeof(dwProcessDebugPort),
				&dwReturned);

			return (NT_SUCCESS(status) && (-1 == dwProcessDebugPort));
		}
	}
	return false;
}

bool Check_NtQueryIP_ProcessDebugFlags()
{
	//https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugflags
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			DWORD dwProcessDebugFlags, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				(PROCESSINFOCLASS)0x1f,//ProcessDebugFlags
				&dwProcessDebugFlags,
				sizeof(DWORD),
				&dwReturned);

			return (NT_SUCCESS(status) && (0 == dwProcessDebugFlags));
		}
	}
	return false;
}


bool Check_NtQueryIP_ProcessDebugObjHandle()
{	
	//https://anti-debug.checkpoint.com/techniques/debug-flags.html#using-win32-api-ntqueryinformationprocess-processdebugobjecthandle
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
			hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			DWORD dwReturned;
			HANDLE hProcessDebugObject = 0;
			const DWORD ProcessDebugObjectHandle = 0x1e;
			NTSTATUS status = pfnNtQueryInformationProcess(
				GetCurrentProcess(),
				(PROCESSINFOCLASS)ProcessDebugObjectHandle,
				&hProcessDebugObject,
				sizeof(HANDLE),
				&dwReturned);

			return (NT_SUCCESS(status) && (0 != hProcessDebugObject));
		}
	}
	return false;
}


bool Check_HeapFlagPreWin10()
{
	//https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection
	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do
	{
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			return false;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}

bool Check_KuserKernDebug()
{
	unsigned char b = *(unsigned char*)0x7ffe02d4;
	return ((b & 0x01) || (b & 0x02));
}