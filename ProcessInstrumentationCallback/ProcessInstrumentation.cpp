#include "ProcessInstrumentation.h"

extern "C" {
    extern INSTRUMENTATION_SHARED_STATE g_hSharedState;
    void NTAPI ProcessInstrumentationStub(void);
}

CProcessInstrumentation::CProcessInstrumentation()
    : m_hProcess(GetCurrentProcess())
    , m_bRegistered(FALSE)
    , m_sharedState(&g_hSharedState)
    , m_lastStatus(STATUS_SUCCESS)
{
}

CProcessInstrumentation::~CProcessInstrumentation()
{
    Cleanup();
}

BOOL CProcessInstrumentation::Initialize()
{
    if (m_bRegistered) {
        return TRUE;
    }

    if (m_sharedState->CallbackOwner != 0 &&
        m_sharedState->CallbackOwner != reinterpret_cast<ULONG64>(this)) {
        m_lastStatus = STATUS_DEVICE_BUSY;
        return FALSE;
    }

    InstrumentationInitializeCpuFeatures();

    InterlockedExchange(&m_sharedState->IsActive, FALSE);
    m_sharedState->CallbackOwner = reinterpret_cast<ULONG64>(this);
    m_sharedState->CallbackCount = 0;
    m_sharedState->LastReturnRip = 0;
    m_sharedState->LastSyscallStatus = 0;

    return RegisterCallback(ProcessInstrumentationStub);
}

void CProcessInstrumentation::Cleanup()
{
    if (m_bRegistered) {
        UnregisterCallback();
    }
}

BOOL CProcessInstrumentation::RegisterCallback(PVOID CallbackRoutine)
{
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION params = {};
    params.Version = 0;
    params.Callback = CallbackRoutine;

    m_lastStatus = NtSetInformationProcess(
        m_hProcess,
        static_cast<PROCESS_INFORMATION_CLASS>(PROCESS_INSTRUMENTATION_CALLBACK),
        &params,
        sizeof(params)
    );

    if (NT_SUCCESS(m_lastStatus)) {
        m_bRegistered = TRUE;
        return TRUE;
    }

    return FALSE;
}

void CProcessInstrumentation::UnregisterCallback()
{
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION params = {};
    m_lastStatus = NtSetInformationProcess(
        m_hProcess,
        static_cast<PROCESS_INFORMATION_CLASS>(PROCESS_INSTRUMENTATION_CALLBACK),
        &params,
        sizeof(params)
    );

    m_bRegistered = FALSE;
    if (m_sharedState->CallbackOwner == reinterpret_cast<ULONG64>(this)) {
        InterlockedExchange(&m_sharedState->IsActive, FALSE);
        m_sharedState->CallbackOwner = 0;
    }
}

void CProcessInstrumentation::Activate()
{
    InterlockedExchange(&m_sharedState->IsActive, TRUE);
}

void CProcessInstrumentation::Deactivate()
{
    InterlockedExchange(&m_sharedState->IsActive, FALSE);
}

const INSTRUMENTATION_SHARED_STATE* CProcessInstrumentation::GetSharedState() const
{
    return m_sharedState;
}
