#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_DEVICE_BUSY
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011L)
#endif

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

// ProcessInstrumentationCallback Information Class (0x28)
#define PROCESS_INSTRUMENTATION_CALLBACK 0x28

// Shared state for activation control
typedef struct _INSTRUMENTATION_SHARED_STATE {
    volatile LONG IsActive;              // Global master switch (0/1), reentrancy is per-thread (TLS)
    ULONG Reserved0;
    volatile ULONG64 CallbackOwner;      // Per-instance owner tag
    volatile ULONG64 CallbackCount;      // Number of callback hits
    volatile ULONG64 LastReturnRip;      // Last user-mode return address (R10)
    volatile LONG64 LastSyscallStatus;   // Last syscall result (RAX/NTSTATUS)
} INSTRUMENTATION_SHARED_STATE, *PINSTRUMENTATION_SHARED_STATE;

// Kernel contract for ProcessInformationClass 0x28 on x64:
// Offset 0x00: Version (ULONG)
// Offset 0x04: Reserved (ULONG)
// Offset 0x08: Callback (PVOID)
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

static_assert(sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION) == 16,
              "Unexpected callback info ABI size");

extern "C" BOOLEAN NTAPI InstrumentationShouldRun(void);
extern "C" void NTAPI InstrumentationRunPayload(
    ULONG_PTR returnRip,
    LONG_PTR syscallStatus
);
extern "C" void NTAPI InstrumentationInitializeCpuFeatures(void);
extern "C" BYTE g_InstrumentationUseAvx;

class CProcessInstrumentation {
public:
    CProcessInstrumentation();
    ~CProcessInstrumentation();

    BOOL Initialize();
    void Cleanup();

    BOOL RegisterCallback(PVOID CallbackRoutine);
    void UnregisterCallback();

    void Activate();
    void Deactivate();
    BOOL IsActive() const { return m_sharedState->IsActive != FALSE; }

    const INSTRUMENTATION_SHARED_STATE* GetSharedState() const;
    NTSTATUS GetLastStatus() const { return m_lastStatus; }

private:
    HANDLE m_hProcess;
    BOOL m_bRegistered;
    PINSTRUMENTATION_SHARED_STATE m_sharedState;
    NTSTATUS m_lastStatus;
};
