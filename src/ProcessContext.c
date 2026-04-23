/*
 * Stealth Kernel Driver - Process Management Implementation
 *
 * Process context management, validation, and lifecycle operations.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "StealthDriver.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, OpenProcessContext)
    #pragma alloc_text(PAGE, CloseProcessContext)
    #pragma alloc_text(PAGE, ValidateProcessContext)
#endif

static LARGE_INTEGER GetProcessContextTime(VOID)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    return now;
}

//------------------------------------------------------------------------------
// OpenProcessContext
//
// Opens and initializes a process context for the specified process.
// Establishes a handle and validates access permissions.
//
// Parameters:
//   ProcessContext   - Output structure for the process context
//   ProcessId        - Target process identifier
//
// Returns:
//   STATUS_SUCCESS on success
//   NTSTATUS error code on failure
//------------------------------------------------------------------------------

NTSTATUS OpenProcessContext(
    OUT PPROCESS_CONTEXT ProcessContext,
    IN ULONG ProcessId
)
{
    NTSTATUS Status;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjectAttributes;

    // Validate input parameters
    if (ProcessContext == NULL || ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ProcessContext, sizeof(PROCESS_CONTEXT));

    // Initialize context identification
    ProcessContext->Tag = PROCESS_CONTEXT_TAG;
    ProcessContext->ProcessId = ProcessId;

    // Initialize context state
    ProcessContext->State = ProcessContextUninitialized;
    ProcessContext->HandleValid = FALSE;

    // Initialize process handles
    ProcessContext->ProcessHandle = NULL;
    ProcessContext->ThreadHandle = NULL;

    // Initialize memory access boundaries
    ProcessContext->BaseAddress = 0x0000000000000000ULL;
    ProcessContext->MaximumAddress = 0x00007FFFFFFFFFFFULL;

    // Initialize operation counters
    ProcessContext->ReadOperations = 0;
    ProcessContext->WriteOperations = 0;
    ProcessContext->TotalOperations = 0;

    // Initialize validation state
    ProcessContext->ValidationState = ProcessValidationPending;
    ProcessContext->LastValidationTime = GetProcessContextTime();

    // Initialize synchronization
    ProcessContext->ReferenceCount = 1;

    // Record context creation time
    ProcessContext->CreationTime = GetProcessContextTime();

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &ProcessContext->ProcessObject);
    if (!NT_SUCCESS(Status)) {
        ProcessContext->State = ProcessContextError;
        ProcessContext->LastError = Status;
        G_DriverState.TotalErrors++;
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    ClientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    ClientId.UniqueThread = NULL;

    Status = ZwOpenProcess(
        &ProcessContext->ProcessHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        &ObjectAttributes,
        &ClientId
    );

    if (IS_SUCCESS(Status)) {
        ProcessContext->State = ProcessContextActive;
        ProcessContext->HandleValid = TRUE;
        ProcessContext->AccessTime = ProcessContext->CreationTime;

        // Mark context as fully initialized
        ProcessContext->ContextFlags |= CONTEXT_FLAG_INITIALIZED;
    }
    else {
        ObDereferenceObject(ProcessContext->ProcessObject);
        ProcessContext->ProcessObject = NULL;

        // Handle initialization failure
        ProcessContext->State = ProcessContextError;
        ProcessContext->LastError = Status;
        G_DriverState.TotalErrors++;
    }

    return Status;
}

//------------------------------------------------------------------------------
// CloseProcessContext
//
// Closes and cleans up resources associated with a process context.
//
// Parameters:
//   ProcessContext   - Process context to close
//------------------------------------------------------------------------------

VOID CloseProcessContext(
    IN PPROCESS_CONTEXT ProcessContext
)
{
    if (ProcessContext == NULL) {
        return;
    }

    // Validate context tag
    if (ProcessContext->Tag != PROCESS_CONTEXT_TAG) {
        return;
    }

    if (ProcessContext->State == ProcessContextClosed ||
        ProcessContext->State == ProcessContextClosing) {
        return;
    }

    // Update context state
    ProcessContext->State = ProcessContextClosing;

    // Decrement reference count safely
    if (ProcessContext->ReferenceCount > 0) {
        InterlockedDecrement(&ProcessContext->ReferenceCount);
    }

    // Update operation statistics
    ProcessContext->TotalOperations =
        ProcessContext->ReadOperations + ProcessContext->WriteOperations;

    // Record closure time
    ProcessContext->ClosureTime = GetProcessContextTime();

    // Clean up handles
    if (ProcessContext->ProcessHandle != NULL) {
        ZwClose(ProcessContext->ProcessHandle);
        ProcessContext->ProcessHandle = NULL;
    }
    ProcessContext->HandleValid = FALSE;

    if (ProcessContext->ThreadHandle != NULL) {
        // Thread handle cleanup would be performed here
        ProcessContext->ThreadHandle = NULL;
    }

    if (ProcessContext->ProcessObject != NULL) {
        ObDereferenceObject(ProcessContext->ProcessObject);
        ProcessContext->ProcessObject = NULL;
    }

    // Mark context as closed
    ProcessContext->State = ProcessContextClosed;
    ProcessContext->ValidationState = ProcessValidationFailed;
    ProcessContext->Tag = 0;

    // Update driver statistics
    G_DriverState.TotalWriteOperations++;
}

//------------------------------------------------------------------------------
// ValidateProcessContext
//
// Validates the integrity and state of a process context.
//
// Parameters:
//   ProcessContext   - Process context to validate
//
// Returns:
//   TRUE if context is valid
//   FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN ValidateProcessContext(
    IN PPROCESS_CONTEXT ProcessContext
)
{
    if (ProcessContext == NULL) {
        return FALSE;
    }

    // Validate context tag
    if (ProcessContext->Tag != PROCESS_CONTEXT_TAG) {
        return FALSE;
    }

    // Validate context state
    if (ProcessContext->State != ProcessContextActive &&
        ProcessContext->State != ProcessContextRunning) {
        return FALSE;
    }

    // Validate handle state
    if (!ProcessContext->HandleValid) {
        return FALSE;
    }

    // Validate process handle
    if (ProcessContext->ProcessHandle == NULL) {
        return FALSE;
    }

    if (ProcessContext->ProcessObject == NULL) {
        return FALSE;
    }

    // Validate reference count
    if (ProcessContext->ReferenceCount < 1) {
        return FALSE;
    }

    // Validate memory access boundaries
    if (ProcessContext->BaseAddress >= ProcessContext->MaximumAddress) {
        return FALSE;
    }

    // Mark validation state
    ProcessContext->ValidationState = ProcessValidationPassed;
    ProcessContext->LastValidationTime = GetProcessContextTime();

    return TRUE;
}
