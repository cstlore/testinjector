#include <Windows.h>
#include <iostream>
#include <intrin.h>
#include <immintrin.h>
#include "ProcessInstrumentation.h"

// Shared state instance (referenced by assembly stub)
extern "C" INSTRUMENTATION_SHARED_STATE g_hSharedState;
INSTRUMENTATION_SHARED_STATE g_hSharedState = {};
static thread_local LONG g_tlsCallbackDepth = 0;
extern "C" BYTE g_InstrumentationUseAvx = 0;

static BOOL QueryAvxSupport()
{
    int cpuInfo[4] = {};
    __cpuidex(cpuInfo, 1, 0);

    const BOOL hasAvx = (cpuInfo[2] & (1 << 28)) != 0;
    const BOOL hasOsxsave = (cpuInfo[2] & (1 << 27)) != 0;
    if (!hasAvx || !hasOsxsave) {
        return FALSE;
    }

    const unsigned __int64 xcr0 = _xgetbv(0);
    const unsigned __int64 avxStateMask = 0x6ULL; // XMM + YMM state enabled by OS
    return (xcr0 & avxStateMask) == avxStateMask;
}

static BOOL CALLBACK InitializeCpuFeaturesOnce(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID* Context
)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    g_InstrumentationUseAvx = QueryAvxSupport() ? 1 : 0;
    return TRUE;
}

extern "C" void NTAPI InstrumentationInitializeCpuFeatures()
{
    static INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;
    (void)InitOnceExecuteOnce(&initOnce, InitializeCpuFeaturesOnce, NULL, NULL);
}

extern "C" BOOLEAN NTAPI InstrumentationShouldRun()
{
    if (InterlockedCompareExchange(&g_hSharedState.IsActive, FALSE, FALSE) == FALSE) {
        return FALSE;
    }

    // Reentrancy guard is thread-local, so concurrent threads do not block each other.
    if (g_tlsCallbackDepth != 0) {
        return FALSE;
    }

    g_tlsCallbackDepth = 1;
    return TRUE;
}

// Payload handler - called on syscall return path.
// Keep this leaf-only: no allocation, no I/O, no locks.
extern "C" void NTAPI ProcessPayloadEntry(
    ULONG_PTR returnRip,
    LONG_PTR syscallStatus
)
{
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&g_hSharedState.CallbackCount));
    g_hSharedState.LastReturnRip = static_cast<ULONG64>(returnRip);
    g_hSharedState.LastSyscallStatus = static_cast<LONG64>(syscallStatus);
}

extern "C" void NTAPI InstrumentationRunPayload(
    ULONG_PTR returnRip,
    LONG_PTR syscallStatus
)
{
    __try {
        ProcessPayloadEntry(returnRip, syscallStatus);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Swallow payload-side faults to preserve control flow in instrumentation path.
    }

    g_tlsCallbackDepth = 0;
}

int main()
{
    std::wcout << L"ProcessInstrumentationCallback Hijack Demo\n"
               << L"==========================================\n\n";

    CProcessInstrumentation instrumentation;

    // Initialize and register the callback
    if (instrumentation.Initialize()) {
        std::wcout << L"[+] Callback registered successfully\n\n";
    }
    else {
        std::wcout << L"[-] Failed to register callback (NTSTATUS: 0x"
                   << std::hex << static_cast<unsigned long>(instrumentation.GetLastStatus())
                   << std::dec << L")\n";
        return 1;
    }

    // Display shared state
    const auto* state = instrumentation.GetSharedState();
    std::wcout << L"[i] Shared state address: 0x"
               << std::hex << reinterpret_cast<ULONG64>(state) << std::dec << L"\n";
    std::wcout << L"[i] Activation status: "
               << (state->IsActive ? L"ACTIVE" : L"INACTIVE") << L"\n";
    std::wcout << L"[i] Callback hits: " << state->CallbackCount << L"\n\n";

    // Activation control demonstration
    std::wcout << L"[->] Activating instrumentation callback...\n";
    instrumentation.Activate();
    std::wcout << L"[i] Activation status: "
               << (instrumentation.IsActive() ? L"ACTIVE" : L"INACTIVE") << L"\n";

    // Trigger a few syscalls after activation to demonstrate callback hits.
    for (int i = 0; i < 32; ++i) {
        Sleep(1);
        (void)GetCurrentProcessId();
    }

    std::wcout << L"[i] Callback hits: " << state->CallbackCount << L"\n";
    std::wcout << L"[i] Last return RIP: 0x"
               << std::hex << state->LastReturnRip << std::dec << L"\n";
    std::wcout << L"[i] Last syscall status: 0x"
               << std::hex << static_cast<unsigned long>(state->LastSyscallStatus)
               << std::dec << L"\n\n";

    // Keep process alive for demonstration
    std::wcout << L"[i] Process instrumentation active. Press Enter to deactivate...\n";
    std::wcin.get();

    instrumentation.Deactivate();
    std::wcout << L"[i] Activation status: "
               << (instrumentation.IsActive() ? L"ACTIVE" : L"INACTIVE") << L"\n\n";

    // Cleanup
    instrumentation.Cleanup();
    std::wcout << L"[+] Cleanup complete\n";

    return 0;
}
