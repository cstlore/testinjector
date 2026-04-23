#include "StealthDriver.h"
#include "SharedSignaling.h"
#include <ntifs.h>

static PSHARED_MEMORY_BUFFER g_pSharedBuffer = NULL;
typedef struct _SHARED_BUFFER_SYNC_CONTEXT {
    EX_PUSH_LOCK Lock;
    KEVENT Event;
} SHARED_BUFFER_SYNC_CONTEXT, *PSHARED_BUFFER_SYNC_CONTEXT;
static PSHARED_BUFFER_SYNC_CONTEXT g_pSharedSyncContext = NULL;

static NTSTATUS ExecuteReadCommand(PSHARED_COMMAND Command);
static NTSTATUS ExecuteWriteCommand(PSHARED_COMMAND Command);
static NTSTATUS ExecuteQueryCommand(PSHARED_COMMAND Command);
static NTSTATUS ExecuteSignalCommand(PSHARED_COMMAND Command);
static PSHARED_BUFFER_SYNC_CONTEXT GetSharedSyncContext(IN PSHARED_MEMORY_BUFFER Buffer);
static NTSTATUS AllocateSharedSyncContext(OUT PSHARED_BUFFER_SYNC_CONTEXT* SyncContext);
static VOID FreeSharedSyncContext(IN OUT PSHARED_BUFFER_SYNC_CONTEXT* SyncContext);
static BOOLEAN IsUserAddressRange(IN CONST VOID* Address, IN SIZE_T Length);
static BOOLEAN ValidateSharedQueueAccess(
    IN PSHARED_MEMORY_BUFFER Buffer,
    IN PSHARED_COMMAND Command,
    IN BOOLEAN CommandWriteAccess
);

static PSHARED_MEMORY_BUFFER GetActiveSharedBuffer(VOID)
{
    if (G_DriverState.SharedBuffer != NULL) {
        return G_DriverState.SharedBuffer;
    }

    return g_pSharedBuffer;
}

static PSHARED_BUFFER_SYNC_CONTEXT GetSharedSyncContext(IN PSHARED_MEMORY_BUFFER Buffer)
{
    if (Buffer == NULL) {
        return NULL;
    }

    if (G_DriverState.SharedBuffer == Buffer) {
        return (PSHARED_BUFFER_SYNC_CONTEXT)G_DriverState.SharedBufferSyncContext;
    }

    if (g_pSharedBuffer == Buffer) {
        return g_pSharedSyncContext;
    }

    return NULL;
}

static NTSTATUS AllocateSharedSyncContext(OUT PSHARED_BUFFER_SYNC_CONTEXT* SyncContext)
{
    PSHARED_BUFFER_SYNC_CONTEXT LocalContext;

    if (SyncContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SyncContext = NULL;
    LocalContext = (PSHARED_BUFFER_SYNC_CONTEXT)ExAllocatePoolUninitialized(
        NonPagedPoolNx,
        sizeof(SHARED_BUFFER_SYNC_CONTEXT),
        SHARED_BUFFER_TAG
    );
    if (LocalContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(LocalContext, sizeof(SHARED_BUFFER_SYNC_CONTEXT));
    ExInitializePushLock(&LocalContext->Lock);
    KeInitializeEvent(&LocalContext->Event, NotificationEvent, FALSE);
    *SyncContext = LocalContext;
    return STATUS_SUCCESS;
}

static VOID FreeSharedSyncContext(IN OUT PSHARED_BUFFER_SYNC_CONTEXT* SyncContext)
{
    if (SyncContext == NULL || *SyncContext == NULL) {
        return;
    }

    ExFreePool(*SyncContext);
    *SyncContext = NULL;
}

static BOOLEAN IsUserAddressRange(IN CONST VOID* Address, IN SIZE_T Length)
{
    ULONG_PTR startAddress;
    ULONG_PTR endAddress;

    if (Address == NULL || Length == 0) {
        return FALSE;
    }

    startAddress = (ULONG_PTR)Address;
    if (startAddress > (MAXULONG_PTR - (Length - 1))) {
        return FALSE;
    }

    endAddress = startAddress + (Length - 1);
    return endAddress <= (ULONG_PTR)MmUserProbeAddress;
}

static BOOLEAN ValidateSharedQueueAccess(
    IN PSHARED_MEMORY_BUFFER Buffer,
    IN PSHARED_COMMAND Command,
    IN BOOLEAN CommandWriteAccess
)
{
    __try {
        if (IsUserAddressRange(Buffer, sizeof(SHARED_MEMORY_BUFFER))) {
            ProbeForRead(Buffer, sizeof(SHARED_MEMORY_BUFFER), __alignof(SHARED_MEMORY_BUFFER));
            ProbeForWrite(Buffer, sizeof(SHARED_MEMORY_BUFFER), __alignof(SHARED_MEMORY_BUFFER));
        }

        if (IsUserAddressRange(Command, sizeof(SHARED_COMMAND))) {
            if (CommandWriteAccess) {
                ProbeForWrite(Command, sizeof(SHARED_COMMAND), __alignof(SHARED_COMMAND));
            } else {
                ProbeForRead(Command, sizeof(SHARED_COMMAND), __alignof(SHARED_COMMAND));
            }
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

NTSTATUS NTAPI PollSharedCommandBuffer_Initialize(OUT PSHARED_COMMAND_BUFFER* ppBuffer)
{
    NTSTATUS Status;
    PSHARED_MEMORY_BUFFER Buffer;
    PSHARED_BUFFER_SYNC_CONTEXT SyncContext;

    if (ppBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Buffer = (PSHARED_MEMORY_BUFFER)ExAllocatePoolUninitialized(
        NonPagedPoolNx,
        sizeof(SHARED_MEMORY_BUFFER),
        SHARED_BUFFER_TAG
    );
    if (Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = InitializeSharedMemoryBuffer(Buffer, SHARED_BUFFER_DEFAULT_SIZE);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(Buffer);
        return Status;
    }

    Status = AllocateSharedSyncContext(&SyncContext);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(Buffer);
        return Status;
    }

    g_pSharedBuffer = Buffer;
    g_pSharedSyncContext = SyncContext;
    if (G_DriverState.SharedBuffer == NULL) {
        G_DriverState.SharedBuffer = Buffer;
        G_DriverState.SharedBufferSyncContext = SyncContext;
        G_DriverState.SharedBufferInitialized = TRUE;
    }
    *ppBuffer = Buffer;
    return STATUS_SUCCESS;
}

VOID NTAPI PollSharedCommandBuffer_Cleanup(IN PSHARED_COMMAND_BUFFER pBuffer)
{
    if (pBuffer == NULL) {
        return;
    }

    if (G_DriverState.SharedBuffer == pBuffer) {
        G_DriverState.SharedBuffer = NULL;
        G_DriverState.SharedBufferSyncContext = NULL;
        G_DriverState.SharedBufferInitialized = FALSE;
        g_pSharedBuffer = NULL;
        g_pSharedSyncContext = NULL;
        // Global state owns buffer lifetime; avoid freeing under active users.
        return;
    }

    if (g_pSharedBuffer == pBuffer) {
        g_pSharedBuffer = NULL;
        FreeSharedSyncContext(&g_pSharedSyncContext);
    }

    ExFreePool(pBuffer);
}

BOOLEAN NTAPI PollSharedCommandBuffer(PSHARED_COMMAND Command)
{
    PSHARED_MEMORY_BUFFER Buffer;

    if (Command == NULL) {
        return FALSE;
    }

    Buffer = GetActiveSharedBuffer();
    if (Buffer == NULL) {
        return FALSE;
    }

    return DequeueSharedCommand(Buffer, Command);
}

BOOLEAN NTAPI SignalSharedCommand(PSHARED_COMMAND Command)
{
    SHARED_COMMAND LocalCommand;
    PSHARED_MEMORY_BUFFER Buffer;

    if (Command == NULL) {
        return FALSE;
    }

    Buffer = GetActiveSharedBuffer();
    if (Buffer == NULL) {
        return FALSE;
    }

    RtlCopyMemory(&LocalCommand, Command, sizeof(SHARED_COMMAND));
    LocalCommand.Checksum = CalculateCommandChecksum(&LocalCommand);
    return EnqueueSharedCommand(Buffer, &LocalCommand);
}

NTSTATUS NTAPI ExecuteSharedCommand(PSHARED_COMMAND Command)
{
    if (Command == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Command->CommandType) {
    case SharedCommandRead:
        return ExecuteReadCommand(Command);
    case SharedCommandWrite:
        return ExecuteWriteCommand(Command);
    case SharedCommandQuery:
        return ExecuteQueryCommand(Command);
    case SharedCommandSignal:
        return ExecuteSignalCommand(Command);
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS ExecuteReadCommand(PSHARED_COMMAND Command)
{
    NTSTATUS status;
    ULONG bytesRead = 0;

    if (Command->BaseAddress == 0 || Command->BufferSize == 0 ||
        Command->BufferSize > sizeof(Command->InlinePayload)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = SecureReadMemory(
        Command->TargetProcessId,
        Command->BaseAddress,
        Command->InlinePayload,
        Command->BufferSize,
        &bytesRead
    );

    if (NT_SUCCESS(status)) {
        Command->Flags |= COMMAND_FLAG_COMPLETED;
    }

    return status;
}

static NTSTATUS ExecuteWriteCommand(PSHARED_COMMAND Command)
{
    NTSTATUS status;
    ULONG bytesWritten = 0;

    if (Command->BaseAddress == 0 || Command->BufferSize == 0 ||
        Command->BufferSize > sizeof(Command->InlinePayload)) {
        return STATUS_INVALID_PARAMETER;
    }

    status = SecureWriteMemory(
        Command->TargetProcessId,
        Command->BaseAddress,
        Command->InlinePayload,
        Command->BufferSize,
        &bytesWritten
    );

    if (NT_SUCCESS(status)) {
        Command->Flags |= COMMAND_FLAG_COMPLETED;
    }

    return status;
}

static NTSTATUS ExecuteQueryCommand(PSHARED_COMMAND Command)
{
    if (Command == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Command->Flags |= COMMAND_FLAG_COMPLETED;
    return STATUS_SUCCESS;
}

static NTSTATUS ExecuteSignalCommand(PSHARED_COMMAND Command)
{
    if (Command == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Command->Flags |= COMMAND_FLAG_COMPLETED;
    return STATUS_SUCCESS;
}

ULONG NTAPI CalculateCommandChecksum(PSHARED_COMMAND Command)
{
    ULONG checksum = 0;
    PUCHAR pData;
    ULONG size;
    ULONG i;

    if (Command == NULL) {
        return 0;
    }

    pData = (PUCHAR)Command;
    size = sizeof(SHARED_COMMAND) - sizeof(ULONG);

    for (i = 0; i < size; i++) {
        checksum = (checksum << 1) | (checksum >> 31);
        checksum += pData[i];
    }

    return checksum;
}

BOOLEAN NTAPI VerifyCommandIntegrity(PSHARED_COMMAND Command)
{
    ULONG computedChecksum;
    ULONG storedChecksum;

    if (Command == NULL) {
        return FALSE;
    }

    storedChecksum = Command->Checksum;
    Command->Checksum = 0;
    computedChecksum = CalculateCommandChecksum(Command);
    Command->Checksum = storedChecksum;

    return (computedChecksum == storedChecksum);
}

BOOLEAN NTAPI WaitForSharedCommand(
    IN PSHARED_COMMAND_BUFFER pBuffer,
    OUT PSHARED_COMMAND pCommand,
    IN ULONG timeoutMs
)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;
    PSHARED_MEMORY_BUFFER Buffer;
    PSHARED_BUFFER_SYNC_CONTEXT SyncContext;

    if (pCommand == NULL) {
        return FALSE;
    }

    Buffer = pBuffer;
    if (Buffer == NULL) {
        Buffer = GetActiveSharedBuffer();
    }

    if (Buffer == NULL) {
        return FALSE;
    }

    SyncContext = GetSharedSyncContext(Buffer);
    if (SyncContext == NULL) {
        return FALSE;
    }

    if (timeoutMs > 0) {
        timeout.QuadPart = -(LONG64)timeoutMs * 10000LL;
    } else {
        timeout.QuadPart = 0;
    }

    status = KeWaitForSingleObject(
        &SyncContext->Event,
        Executive,
        KernelMode,
        FALSE,
        timeout.QuadPart != 0 ? &timeout : NULL
    );

    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT) {
        return FALSE;
    }

    return DequeueSharedCommand(Buffer, pCommand);
}

NTSTATUS NTAPI InitializeSharedSignaling(
    IN PDRIVER_GLOBAL_STATE GlobalState
)
{
    NTSTATUS Status;
    PSHARED_BUFFER_SYNC_CONTEXT SyncContext;
    BOOLEAN BufferAllocated = FALSE;

    if (GlobalState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (GlobalState->SharedBuffer == NULL) {
        BufferAllocated = TRUE;
        GlobalState->SharedBuffer = (PSHARED_MEMORY_BUFFER)ExAllocatePoolUninitialized(
            NonPagedPoolNx,
            sizeof(SHARED_MEMORY_BUFFER),
            SHARED_BUFFER_TAG
        );
        if (GlobalState->SharedBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = InitializeSharedMemoryBuffer(GlobalState->SharedBuffer, SHARED_BUFFER_DEFAULT_SIZE);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(GlobalState->SharedBuffer);
            GlobalState->SharedBuffer = NULL;
            return Status;
        }
    }

    if (GlobalState->SharedBufferSyncContext == NULL) {
        Status = AllocateSharedSyncContext(&SyncContext);
        if (!NT_SUCCESS(Status)) {
            if (BufferAllocated && GlobalState->SharedBuffer != NULL) {
                ExFreePool(GlobalState->SharedBuffer);
                GlobalState->SharedBuffer = NULL;
            }
            return Status;
        }

        GlobalState->SharedBufferSyncContext = SyncContext;
    }

    g_pSharedBuffer = GlobalState->SharedBuffer;
    g_pSharedSyncContext = (PSHARED_BUFFER_SYNC_CONTEXT)GlobalState->SharedBufferSyncContext;
    GlobalState->SharedBufferInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID NTAPI CleanupSharedSignaling(
    IN PDRIVER_GLOBAL_STATE GlobalState
)
{
    PSHARED_BUFFER_SYNC_CONTEXT SyncContext;

    if (GlobalState != NULL && g_pSharedBuffer == GlobalState->SharedBuffer) {
        g_pSharedBuffer = NULL;
        g_pSharedSyncContext = NULL;
    }

    if (GlobalState != NULL) {
        SyncContext = (PSHARED_BUFFER_SYNC_CONTEXT)GlobalState->SharedBufferSyncContext;
        FreeSharedSyncContext(&SyncContext);
        GlobalState->SharedBufferSyncContext = NULL;
        GlobalState->SharedBufferInitialized = FALSE;
    }
}

BOOLEAN NTAPI EnqueueSharedCommand(
    IN PSHARED_MEMORY_BUFFER Buffer,
    IN PSHARED_COMMAND Command
)
{
    ULONG localHead;
    ULONG localTail;
    ULONG nextTail;
    ULONG queueSize;
    PSHARED_BUFFER_SYNC_CONTEXT SyncContext;
    BOOLEAN result;

    if (Buffer == NULL || Command == NULL) {
        return FALSE;
    }

    if (!ValidateSharedQueueAccess(Buffer, Command, FALSE)) {
        return FALSE;
    }

    SyncContext = GetSharedSyncContext(Buffer);
    if (SyncContext == NULL) {
        return FALSE;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    result = FALSE;
    queueSize = SIZEOF_ARRAY(Buffer->CommandQueue);
    ExAcquirePushLockExclusive(&SyncContext->Lock);

    __try {
        if (!Buffer->QueueInitialized) {
            result = FALSE;
        } else {
            // Snapshot shared indices once under lock to avoid TOCTOU on shared memory.
            localHead = Buffer->QueueHead;
            localTail = Buffer->QueueTail;

            if (localHead >= queueSize || localTail >= queueSize) {
                // Corrupted shared state: reset queue to a known-safe state.
                Buffer->QueueHead = 0;
                Buffer->QueueTail = 0;
                result = FALSE;
            } else {
                nextTail = (localTail + 1) % queueSize;
                if (nextTail == localHead) {
                    result = FALSE;
                } else {
                    RtlCopyMemory(&Buffer->CommandQueue[localTail], Command, sizeof(SHARED_COMMAND));
                    Buffer->QueueTail = nextTail;
                    result = TRUE;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }

    ExReleasePushLockExclusive(&SyncContext->Lock);

    if (result) {
        KeSetEvent(&SyncContext->Event, IO_NO_INCREMENT, FALSE);
    }

    return result;
}

BOOLEAN NTAPI DequeueSharedCommand(
    IN PSHARED_MEMORY_BUFFER Buffer,
    OUT PSHARED_COMMAND Command
)
{
    ULONG localHead;
    ULONG localTail;
    ULONG queueSize;
    PSHARED_BUFFER_SYNC_CONTEXT SyncContext;
    BOOLEAN result;

    if (Buffer == NULL || Command == NULL) {
        return FALSE;
    }

    if (!ValidateSharedQueueAccess(Buffer, Command, TRUE)) {
        return FALSE;
    }

    SyncContext = GetSharedSyncContext(Buffer);
    if (SyncContext == NULL) {
        return FALSE;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    result = FALSE;
    queueSize = SIZEOF_ARRAY(Buffer->CommandQueue);
    ExAcquirePushLockExclusive(&SyncContext->Lock);

    __try {
        if (!Buffer->QueueInitialized) {
            result = FALSE;
        } else {
            // Snapshot shared indices once under lock to avoid TOCTOU on shared memory.
            localHead = Buffer->QueueHead;
            localTail = Buffer->QueueTail;

            if (localHead >= queueSize || localTail >= queueSize) {
                // Corrupted shared state: reset queue to a known-safe state.
                Buffer->QueueHead = 0;
                Buffer->QueueTail = 0;
                result = FALSE;
            } else if (localHead == localTail) {
                result = FALSE;
            } else {
                RtlCopyMemory(Command, &Buffer->CommandQueue[localHead], sizeof(SHARED_COMMAND));
                Buffer->QueueHead = (localHead + 1) % queueSize;
                result = TRUE;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }

    ExReleasePushLockExclusive(&SyncContext->Lock);
    return result;
}
