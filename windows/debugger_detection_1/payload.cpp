#include <string>
#include <vector>
#include "detection_routines.h"

#define PREFIX_DETECTED "FLAG_DBG_DETECTED_"
#define PREFIX_UNDETECTED "FLAG_DBG_UNDETECTED_"
#define FLAG_SUFFIX         "_FLAG"

#define EMIT_FLAG(name, result) \
    if (result) { \
        OutputDebugStringA(PREFIX_DETECTED #name FLAG_SUFFIX); \
    } else { \
        OutputDebugStringA(PREFIX_UNDETECTED #name FLAG_SUFFIX); \
    }


int main() 
{
    OutputDebugStringA("FLAG_DBG_PAYLOAD_STARTED_SUCCESS");
    EMIT_FLAG(ISDBPR, Check_IsDebuggerPresent());
    EMIT_FLAG(ISRDBP, Check_IsRemoteDebuggerPresent());
    EMIT_FLAG(NTQIPPDB, Check_NtQueryIP_ProcessDebugPort());
    EMIT_FLAG(NTQIPPDF, Check_NtQueryIP_ProcessDebugFlags());
    EMIT_FLAG(NTQIPDOH, Check_NtQueryIP_ProcessDebugObjHandle());
    EMIT_FLAG(HPFLGPRE10, Check_HeapFlagPreWin10());
    EMIT_FLAG(KUSERKERNDBG, Check_KuserKernDebug());
    OutputDebugStringA("FLAG_DBG_PAYLOAD_ENDED_SUCCESS");
    return 0;
}