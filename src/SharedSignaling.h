#pragma once

#include "TypeDefinitions.h"
#include <ntifs.h>

/**
 * @file SharedSignaling.h
 * @brief Data-only signaling mechanism via shared memory command buffer
 *
 * Implements a polling-based signaling mechanism that operates without
 * traditional IOCTL/IRP mechanisms. Uses shared memory for command
 * communication between components with sequence-based synchronization.
 */

typedef SHARED_MEMORY_BUFFER SHARED_COMMAND_BUFFER;
typedef PSHARED_MEMORY_BUFFER PSHARED_COMMAND_BUFFER;

/**
 * Command flags
 */
#define COMMAND_FLAG_COMPLETED    0x00000001  // Operation completed successfully
#define COMMAND_FLAG_PENDING      0x00000002  // Operation pending execution
#define COMMAND_FLAG_ERROR        0x00000004  // Operation encountered error
#define COMMAND_FLAG_ASYNC        0x00000008  // Asynchronous operation

/**
 * Initialize the shared signaling mechanism
 *
 * @param ppBuffer Output pointer to receive initialized buffer instance
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS NTAPI PollSharedCommandBuffer_Initialize(
    _Out_ PSHARED_COMMAND_BUFFER* ppBuffer
);

/**
 * Cleanup the shared signaling mechanism
 *
 * @param pBuffer Pointer to the shared command buffer instance
 */
VOID NTAPI PollSharedCommandBuffer_Cleanup(
    _In_opt_ PSHARED_COMMAND_BUFFER pBuffer
);

/**
 * Poll the shared command buffer for new commands
 *
 * Non-blocking check for pending commands in the shared buffer.
 *
 * @param Command Output pointer to receive the polled command
 * @return TRUE if a new command is available, FALSE otherwise
 */
BOOLEAN NTAPI PollSharedCommandBuffer(
    _Out_ PSHARED_COMMAND Command
);

/**
 * Signal a new command in the shared buffer
 *
 * Writes a command to the shared buffer and notifies waiting consumers.
 *
 * @param Command Pointer to the command to signal
 * @return TRUE if command was signaled successfully, FALSE otherwise
 */
BOOLEAN NTAPI SignalSharedCommand(
    _In_ PSHARED_COMMAND Command
);

/**
 * Execute a shared command based on its type
 *
 * Dispatches command execution to appropriate handler based on CommandType.
 *
 * @param Command Pointer to the command to execute
 * @return NTSTATUS code indicating execution result
 */
NTSTATUS NTAPI ExecuteSharedCommand(
    _In_ PSHARED_COMMAND Command
);

/**
 * Calculate checksum for command integrity verification
 *
 * @param Command Pointer to the command
 * @return Checksum value
 */
ULONG NTAPI CalculateCommandChecksum(
    _In_ PSHARED_COMMAND Command
);

/**
 * Verify command integrity using checksum
 *
 * @param Command Pointer to the command to verify
 * @return TRUE if integrity check passes, FALSE otherwise
 */
BOOLEAN NTAPI VerifyCommandIntegrity(
    _In_ PSHARED_COMMAND Command
);

/**
 * Wait for a command with timeout
 *
 * @param pBuffer Pointer to the shared command buffer
 * @param pCommand Output pointer to receive the command
 * @param timeoutMs Timeout in milliseconds (0 for infinite wait)
 * @return TRUE if command was received within timeout, FALSE otherwise
 */
BOOLEAN NTAPI WaitForSharedCommand(
    _In_ PSHARED_COMMAND_BUFFER pBuffer,
    _Out_ PSHARED_COMMAND pCommand,
    _In_ ULONG timeoutMs
);

VOID NTAPI CleanupSharedSignaling(
    _In_opt_ PDRIVER_GLOBAL_STATE GlobalState
);
