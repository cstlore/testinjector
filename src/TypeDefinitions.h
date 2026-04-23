#pragma once

/*
 * Stealth Kernel Driver - Type Definitions
 *
 * Contains Windows-specific type structures, memory operation enums,
 * shared command types, and process context structures.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include <ntdef.h>
#include <ntifs.h>
#include <wdfdrivr.h>
#include "Constants.h"

//------------------------------------------------------------------------------
// Core Memory Operation Types
//------------------------------------------------------------------------------

typedef enum _MEMORY_OPERATION {
    MemoryOperationRead = 1,
    MemoryOperationWrite = 2,
    MemoryOperationQuery = 3,
    MemoryOperationProtect = 4,
    MemoryOperationCommit = 5,
    MemoryOperationDecommit = 6
} MEMORY_OPERATION, *PMEMORY_OPERATION;

//------------------------------------------------------------------------------
// Shared Command Types
//------------------------------------------------------------------------------

typedef enum _SHARED_COMMAND_TYPE {
    SharedCommandRead = 0x01,
    SharedCommandWrite = 0x02,
    SharedCommandQuery = 0x03,
    SharedCommandSignal = 0x04,
    SharedCommandSync = 0x05,
    SharedCommandNoop = 0x06
} SHARED_COMMAND_TYPE, *PSHARED_COMMAND_TYPE;

//------------------------------------------------------------------------------
// Process Handle Structure
//------------------------------------------------------------------------------

typedef enum _PROCESS_CONTEXT_STATE {
    ProcessContextUninitialized = 0,
    ProcessContextActive = 1,
    ProcessContextRunning = 2,
    ProcessContextClosing = 3,
    ProcessContextClosed = 4,
    ProcessContextError = 5
} PROCESS_CONTEXT_STATE, *PPROCESS_CONTEXT_STATE;

typedef enum _PROCESS_VALIDATION_STATE {
    ProcessValidationPending = 0,
    ProcessValidationPassed = 1,
    ProcessValidationFailed = 2
} PROCESS_VALIDATION_STATE, *PPROCESS_VALIDATION_STATE;

typedef struct _PROCESS_CONTEXT {
    ULONG Tag;
    PROCESS_CONTEXT_STATE State;
    ULONG ProcessId;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    BOOLEAN HandleValid;
    LARGE_INTEGER AccessTime;
    LONG ReferenceCount;
    PEPROCESS ProcessObject;
    ULONG PriorityClass;
    ULONG SessionId;
    UNICODE_STRING ProcessName;
    ULONG ReadOperations;
    ULONG WriteOperations;
    ULONG TotalOperations;
    PROCESS_VALIDATION_STATE ValidationState;
    LARGE_INTEGER LastValidationTime;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER ClosureTime;
    ULONG ContextFlags;
    NTSTATUS LastError;
    ULONGLONG BaseAddress;
    ULONGLONG MaximumAddress;
} PROCESS_CONTEXT, *PPROCESS_CONTEXT;

//------------------------------------------------------------------------------
// Shared Command Structure
//------------------------------------------------------------------------------

typedef struct _SHARED_COMMAND {
    // Command identification
    SHARED_COMMAND_TYPE CommandType;
    ULONG CommandId;
    ULONG SequenceNumber;

    // Target specification
    ULONGLONG BaseAddress;
    ULONG BufferSize;
    ULONG TargetProcessId;

    // Operation flags
    ULONG Flags;
    ULONG Status;

    // Integrity
    ULONG Checksum;
    ULONG ChecksumAlgorithm;

    // Timestamp for ordering
    LARGE_INTEGER Timestamp;

    // Payload pointer (for large data)
    PVOID Payload;
    ULONG PayloadSize;

    // Inline payload buffer for small commands
    UCHAR InlinePayload[256];

    // Reserved for future use
    ULONG Reserved[4];
} SHARED_COMMAND, *PSHARED_COMMAND;

//------------------------------------------------------------------------------
// Shared Memory Buffer Structure
//------------------------------------------------------------------------------

typedef struct _SHARED_MEMORY_BUFFER {
    // Buffer identification
    ULONG Tag;
    ULONG BufferSize;
    ULONG BufferOffset;

    // State tracking
    ULONG State;
    LARGE_INTEGER LastAccessTime;
    ULONG ReferenceCount;

    // Command queue
    SHARED_COMMAND CommandQueue[16];
    ULONG QueueHead;
    ULONG QueueTail;
    BOOLEAN QueueInitialized;

    // Memory region tracking
    ULONGLONG RegionBase;
    ULONGLONG RegionSize;
    PVOID MappingAddress;

    // Checksum validation
    ULONG BufferChecksum;

    // Reserved
    UCHAR Reserved[256];
} SHARED_MEMORY_BUFFER, *PSHARED_MEMORY_BUFFER;

typedef struct _DRIVER_GLOBAL_STATE DRIVER_GLOBAL_STATE, *PDRIVER_GLOBAL_STATE;

typedef struct _DRIVER_DEVICE_EXTENSION {
    PDRIVER_GLOBAL_STATE GlobalState;
    ULONG Signature;
} DRIVER_DEVICE_EXTENSION, *PDRIVER_DEVICE_EXTENSION;

//------------------------------------------------------------------------------
// Manual Mapping Entry Structure
//------------------------------------------------------------------------------

typedef struct _MANUAL_MAPPING_ENTRY {
    // Mapping identification
    ULONG Tag;
    ULONG MappingFlags;

    // Memory mapping
    PVOID MappingBase;
    ULONG MappingSize;
    ULONG CommitSize;

    // PE header information
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    IMAGE_SECTION_HEADER* FirstSection;
    ULONG SectionCount;

    // Import resolution
    BOOLEAN ImportsResolved;
    PIMAGE_IMPORT_DESCRIPTOR FirstImport;
    ULONG ImportDescriptorCount;

    // Entry point
    PVOID EntryPoint;
    BOOLEAN EntryPointResolved;

    // Driver extension reference
    PDRIVER_EXTENSION DriverExtension;

    // Timestamps
    LARGE_INTEGER LoadTime;
    LARGE_INTEGER LastAccessTime;

    // Reference counting
    LONG ReferenceCount;

    // Reserved
    ULONG Reserved[8];
} MANUAL_MAPPING_ENTRY, *PMANUAL_MAPPING_ENTRY;

//------------------------------------------------------------------------------
// Memory Operation Result Structure
//------------------------------------------------------------------------------

typedef struct _MEMORY_OPERATION_RESULT {
    NTSTATUS Status;
    MEMORY_OPERATION OperationType;

    // Address information
    ULONGLONG TargetAddress;
    ULONG RequestedSize;
    ULONG CompletedSize;

    // Timing
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    ULONG DurationMicroseconds;

    // Statistics
    ULONG PageFaults;
    ULONG PagesCommitted;
    ULONG ProtectionFlags;
    ULONG BufferChecksum;

    // Extended information
    PVOID ExtendedInfo;
    ULONG ExtendedInfoSize;
} MEMORY_OPERATION_RESULT, *PMEMORY_OPERATION_RESULT;

//------------------------------------------------------------------------------
// Erasure Operation Context
//------------------------------------------------------------------------------

typedef struct _ERASURE_CONTEXT {
    // Operation flags
    ULONG ErasureFlags;
    ULONG CompletedFlags;

    // PiDDBCacheTable context
    PVOID PiDDBCacheBase;
    ULONG PiDDBCacheSize;
    ULONG PiDDBCacheEntriesProcessed;

    // KernelHashBucketList context
    PVOID HashBucketBase;
    ULONG HashBucketCount;
    ULONG HashBucketsCleared;

    // MmUnloadedDrivers context
    PVOID UnloadedDriverBase;
    ULONG UnloadedDriverCount;
    ULONG DriversErased;

    // Statistics
    ULONG TotalBytesErased;
    ULONG EntriesProcessed;
    ULONG ErrorsEncountered;

    // Timing
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;

    // Reserved
    ULONG Reserved[4];
} ERASURE_CONTEXT, *PERASURE_CONTEXT;

//------------------------------------------------------------------------------
// Hash Bucket Entry Structure
//------------------------------------------------------------------------------

typedef struct _HASH_BUCKET_ENTRY {
    struct _HASH_BUCKET_ENTRY* Next;
    struct _HASH_BUCKET_ENTRY* Prev;

    // Entry key
    ULONG HashKey;
    PVOID EntryData;
    ULONG EntrySize;

    // Timestamp
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;

    // Reference count
    LONG ReferenceCount;

    // Flags
    ULONG Flags;

    // Reserved
    ULONG Reserved[2];
} HASH_BUCKET_ENTRY, *PHASH_BUCKET_ENTRY;

typedef struct _HASH_BUCKET_LIST {
    HASH_BUCKET_ENTRY* Entries[HASH_BUCKET_COUNT];
    ULONG TotalEntryCount;
    ULONG OccupiedBucketCount;
    EX_SPIN_LOCK Lock;
} HASH_BUCKET_LIST, *PHASH_BUCKET_LIST;

//------------------------------------------------------------------------------
// Cache Table Entry Structure
//------------------------------------------------------------------------------

typedef struct _CACHE_TABLE_ENTRY {
    // Entry key
    UNICODE_STRING DevicePath;
    PVOID DeviceObject;

    // Cached data
    PVOID CachedData;
    ULONG CachedDataSize;

    // Timestamps
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER ExpirationTime;

    // State
    ULONG State;
    BOOLEAN IsDirty;

    // Reference count
    LONG ReferenceCount;

    // List linkage
    LIST_ENTRY ListEntry;

    // Reserved
    ULONG Reserved[4];
} CACHE_TABLE_ENTRY, *PCACHE_TABLE_ENTRY;

//------------------------------------------------------------------------------
// Unloaded Driver Entry Structure
//------------------------------------------------------------------------------

typedef struct _UNLOADED_DRIVER_ENTRY {
    // Driver identification
    UNICODE_STRING DriverName;
    USHORT DriverNameLength;

    // Memory range
    ULONGLONG StartAddress;
    ULONGLONG EndAddress;
    ULONG ImageSize;

    // Checksum information
    ULONG CheckSum;
    ULONG TimeDateStamp;

    // Module characteristics
    ULONG Characteristics;

    // Section information
    USHORT NumberOfSections;

    // List linkage
    LIST_ENTRY ListEntry;

    // Timestamp
    LARGE_INTEGER UnloadTime;

    // Reserved
    ULONG Reserved[4];
} UNLOADED_DRIVER_ENTRY, *PUNLOADED_DRIVER_ENTRY;

//------------------------------------------------------------------------------
// Driver Global State Structure
//------------------------------------------------------------------------------

struct _DRIVER_GLOBAL_STATE {
    // Driver identification
    UNICODE_STRING DriverName;
    ULONG DriverVersion;
    LARGE_INTEGER LoadTime;
    BOOLEAN Initialized;

    // Mapping state
    PMANUAL_MAPPING_ENTRY CurrentMapping;
    BOOLEAN IsManuallyMapped;

    // Shared buffer state
    PSHARED_MEMORY_BUFFER SharedBuffer;
    PVOID SharedBufferSyncContext;
    BOOLEAN SharedBufferInitialized;
    ULONG AccessState;

    // Operation counters
    ULONG TotalReadOperations;
    ULONG TotalWriteOperations;
    ULONG TotalErasureOperations;
    ULONG TotalCommandProcessed;

    // Error counters
    ULONG TotalErrors;
    ULONG TotalTimeouts;
    ULONG TotalValidationErrors;

    // Synchronization
    EX_PUSH_LOCK GlobalLock;

    // Callback pointers
    PVOID ReadCallback;
    PVOID WriteCallback;
    PVOID ErasureCallback;

    // Reserved
    UCHAR Reserved[512];
};

//------------------------------------------------------------------------------
// Memory Region Descriptor
//------------------------------------------------------------------------------

typedef struct _MEMORY_REGION_DESCRIPTOR {
    ULONGLONG BaseAddress;
    ULONGLONG RegionSize;
    ULONGLONG AllocationBase;
    ULONG AllocationProtect;
    ULONG State;
    ULONG Protect;
    ULONG Type;

    // Subsection information
    ULONG SubsectionCount;
    PVOID SubsectionArray;

    // Private data
    PVOID PrivateData;
    ULONG PrivateDataSize;

    // Flags
    ULONG Flags;

    // Reserved
    ULONG Reserved[4];
} MEMORY_REGION_DESCRIPTOR, *PMEMORY_REGION_DESCRIPTOR;
