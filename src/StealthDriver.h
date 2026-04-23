#pragma once

/*
 * Stealth Kernel Driver - Main Header
 *
 * Core driver type definitions, function declarations, and module interfaces
 * for the stealth memory operations driver with manual mapping support.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "Constants.h"
#include "TypeDefinitions.h"

extern DRIVER_GLOBAL_STATE G_DriverState;

typedef struct _READ_MEMORY_INPUT {
    ULONG ProcessId;
    ULONGLONG SourceAddress;
    PVOID DestinationBuffer;
    ULONG BufferSize;
} READ_MEMORY_INPUT, *PREAD_MEMORY_INPUT;

typedef struct _WRITE_MEMORY_INPUT {
    ULONG ProcessId;
    ULONGLONG DestinationAddress;
    PVOID SourceBuffer;
    ULONG BufferSize;
} WRITE_MEMORY_INPUT, *PWRITE_MEMORY_INPUT;

typedef struct _QUERY_MEMORY_INPUT {
    ULONG ProcessId;
    ULONGLONG Address;
} QUERY_MEMORY_INPUT, *PQUERY_MEMORY_INPUT;

typedef struct _PROTECT_MEMORY_INPUT {
    ULONG ProcessId;
    ULONGLONG BaseAddress;
    ULONG RegionSize;
    ULONG NewProtection;
} PROTECT_MEMORY_INPUT, *PPROTECT_MEMORY_INPUT;

typedef struct _DRIVER_STATE_QUERY {
    ULONG DriverVersion;
    ULONG TotalReadOperations;
    ULONG TotalWriteOperations;
    ULONG TotalErasureOperations;
    ULONG TotalCommandProcessed;
    ULONG TotalErrors;
    ULONG TotalTimeouts;
    LARGE_INTEGER LoadTime;
} DRIVER_STATE_QUERY, *PDRIVER_STATE_QUERY;

//------------------------------------------------------------------------------
// Manual Mapping Entry Point Declaration
//------------------------------------------------------------------------------

/*
 * Custom entry point for manual mapping support.
 * This replaces the standard DriverEntry for scenarios requiring
 * non-standard loading mechanisms.
 */
VOID NTAPI DriverMapEntry(
    IN PVOID MappingBase,
    IN ULONG MappingSize,
    IN PDRIVER_EXTENSION DriverExtension
);

//------------------------------------------------------------------------------
// Driver Initialization Functions
//------------------------------------------------------------------------------

NTSTATUS InitializeDriverGlobalState(
    IN PDRIVER_GLOBAL_STATE GlobalState
);

NTSTATUS InitializeSharedMemoryBuffer(
    IN OUT PSHARED_MEMORY_BUFFER Buffer,
    IN ULONG BufferSize
);

VOID CleanupDriverGlobalState(
    IN PDRIVER_GLOBAL_STATE GlobalState
);

//------------------------------------------------------------------------------
// Mapping Management Functions
//------------------------------------------------------------------------------

NTSTATUS CreateManualMapping(
    OUT PMANUAL_MAPPING_ENTRY MappingEntry,
    IN PVOID MappingBase,
    IN ULONG MappingSize
);

VOID ReleaseManualMapping(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
);

NTSTATUS ResolveImports(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
);

BOOLEAN IsMappingValid(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
);

//------------------------------------------------------------------------------
// Memory Operation Function Declarations
//------------------------------------------------------------------------------

NTSTATUS SecureReadMemory(
    IN ULONG ProcessId,
    IN ULONGLONG SourceAddress,
    OUT PVOID DestinationBuffer,
    IN ULONG BufferSize,
    OUT PULONG BytesRead
);

NTSTATUS SecureWriteMemory(
    IN ULONG ProcessId,
    IN ULONGLONG DestinationAddress,
    IN PVOID SourceBuffer,
    IN ULONG BufferSize,
    OUT PULONG BytesWritten
);

NTSTATUS QueryMemoryInformation(
    IN ULONG ProcessId,
    IN ULONGLONG Address,
    OUT PMEMORY_REGION_DESCRIPTOR RegionDescriptor
);

NTSTATUS ProtectMemoryRegion(
    IN ULONG ProcessId,
    IN ULONGLONG BaseAddress,
    IN ULONG RegionSize,
    IN ULONG NewProtection
);

//------------------------------------------------------------------------------
// Erasure Function Declarations
//------------------------------------------------------------------------------

VOID ErasePiDDBCacheTable(
    IN PVOID CacheTable
);

VOID EraseKernelHashBucketList(
    IN USHORT HashBucketIndex
);

VOID EraseMmUnloadedDrivers(
    IN ULONG UnloadedDriverCount
);

NTSTATUS ExecuteErasureOperations(
    IN OUT PERASURE_CONTEXT ErasureContext
);

VOID ClearErasureStatistics(
    IN PERASURE_CONTEXT ErasureContext
);

//------------------------------------------------------------------------------
// Shared Signaling Function Declarations
//------------------------------------------------------------------------------

BOOLEAN NTAPI PollSharedCommandBuffer(
    OUT PSHARED_COMMAND Command
);

BOOLEAN NTAPI SignalSharedCommand(
    IN PSHARED_COMMAND Command
);

NTSTATUS NTAPI ExecuteSharedCommand(
    IN PSHARED_COMMAND Command
);

BOOLEAN NTAPI EnqueueSharedCommand(
    IN PSHARED_MEMORY_BUFFER Buffer,
    IN PSHARED_COMMAND Command
);

BOOLEAN NTAPI DequeueSharedCommand(
    IN PSHARED_MEMORY_BUFFER Buffer,
    OUT PSHARED_COMMAND Command
);

NTSTATUS NTAPI InitializeSharedSignaling(
    IN PDRIVER_GLOBAL_STATE GlobalState
);

VOID NTAPI CleanupSharedSignaling(
    IN PDRIVER_GLOBAL_STATE GlobalState
);

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
);

NTSTATUS DriverAddDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT PhysicalDeviceObject
);

VOID DriverCleanup(
    IN PDRIVER_OBJECT DriverObject
);

//------------------------------------------------------------------------------
// Process Management Function Declarations
//------------------------------------------------------------------------------

NTSTATUS OpenProcessContext(
    OUT PPROCESS_CONTEXT ProcessContext,
    IN ULONG ProcessId
);

VOID CloseProcessContext(
    IN PPROCESS_CONTEXT ProcessContext
);

BOOLEAN ValidateProcessContext(
    IN PPROCESS_CONTEXT ProcessContext
);

//------------------------------------------------------------------------------
// Utility Function Declarations
//------------------------------------------------------------------------------

ULONG ComputeChecksum(
    IN PVOID Buffer,
    IN ULONG BufferSize,
    IN ULONG Algorithm
);

VOID InitializeHashBucketList(
    OUT PHASH_BUCKET_LIST BucketList
);

VOID CleanupHashBucketList(
    IN PHASH_BUCKET_LIST BucketList
);

BOOLEAN AddHashBucketEntry(
    IN PHASH_BUCKET_LIST BucketList,
    IN PHASH_BUCKET_ENTRY Entry
);

PHASH_BUCKET_ENTRY FindHashBucketEntry(
    IN PHASH_BUCKET_LIST BucketList,
    IN ULONG HashKey
);

//------------------------------------------------------------------------------
// Logging and Debugging
//------------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, InitializeDriverGlobalState)
    #pragma alloc_text(INIT, InitializeSharedMemoryBuffer)
    #pragma alloc_text(PAGE, CreateManualMapping)
    #pragma alloc_text(PAGE, SecureReadMemory)
    #pragma alloc_text(PAGE, SecureWriteMemory)
    #pragma alloc_text(PAGE, ErasePiDDBCacheTable)
    #pragma alloc_text(PAGE, EraseKernelHashBucketList)
    #pragma alloc_text(PAGE, EraseMmUnloadedDrivers)
    #pragma alloc_text(PAGE, PollSharedCommandBuffer)
    #pragma alloc_text(PAGE, ExecuteSharedCommand)
#endif // ALLOC_PRAGMA

//------------------------------------------------------------------------------
// Module Export Definitions
//------------------------------------------------------------------------------

#ifdef STEALTH_DRIVER_EXPORTS

    __declspec(dllexport) VOID NTAPI DriverMapEntry(
        IN PVOID MappingBase,
        IN ULONG MappingSize,
        IN PDRIVER_EXTENSION DriverExtension
    );

    __declspec(dllexport) NTSTATUS SecureReadMemory(
        IN ULONG ProcessId,
        IN ULONGLONG SourceAddress,
        OUT PVOID DestinationBuffer,
        IN ULONG BufferSize,
        OUT PULONG BytesRead
    );

    __declspec(dllexport) NTSTATUS SecureWriteMemory(
        IN ULONG ProcessId,
        IN ULONGLONG DestinationAddress,
        IN PVOID SourceBuffer,
        IN ULONG BufferSize,
        OUT PULONG BytesWritten
    );

    __declspec(dllexport) VOID ErasePiDDBCacheTable(
        IN PVOID CacheTable
    );

    __declspec(dllexport) VOID EraseKernelHashBucketList(
        IN USHORT HashBucketIndex
    );

    __declspec(dllexport) VOID EraseMmUnloadedDrivers(
        IN ULONG UnloadedDriverCount
    );

    __declspec(dllexport) BOOLEAN PollSharedCommandBuffer(
        OUT PSHARED_COMMAND Command
    );

    __declspec(dllexport) NTSTATUS ExecuteSharedCommand(
        IN PSHARED_COMMAND Command
    );

#endif // STEALTH_DRIVER_EXPORTS
