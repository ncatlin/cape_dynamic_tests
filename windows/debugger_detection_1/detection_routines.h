#pragma once
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

bool Check_IsDebuggerPresent();
bool Check_IsRemoteDebuggerPresent();
bool Check_NtQueryIP_ProcessDebugPort();
bool Check_NtQueryIP_ProcessDebugFlags();
bool Check_NtQueryIP_ProcessDebugObjHandle();
bool Check_HeapFlagPreWin10();
bool Check_HeapFlag();
bool Check_KuserKernDebug();