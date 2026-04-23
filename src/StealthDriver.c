/*
 * Stealth Kernel Driver - Main Implementation
 *
 * Core driver implementation with custom DriverMapEntry entry point
 * for manual mapping support.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "StealthDriver.h"

//------------------------------------------------------------------------------
// Global Driver State
//------------------------------------------------------------------------------

DRIVER_GLOBAL_STATE G_DriverState;

//------------------------------------------------------------------------------
// Forward Declarations
//------------------------------------------------------------------------------

static LARGE_INTEGER GetSystemTimeSnapshot(VOID)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    return now;
}

static PVOID ResolveImagePointerFromRva(
    IN PMANUAL_MAPPING_ENTRY MappingEntry,
    IN ULONG Rva,
    IN ULONG RequiredSize
)
{
    ULONG Index;
    PIMAGE_SECTION_HEADER Section;
    ULONG SectionSpan;
    ULONG Delta;
    ULONG RawOffset;

    if (MappingEntry == NULL || MappingEntry->NtHeaders == NULL) {
        return NULL;
    }

    if (RequiredSize > MappingEntry->MappingSize) {
        return NULL;
    }

    // Case 2: raw file mapping; convert RVA through section raw offsets.
    for (Index = 0; Index < MappingEntry->SectionCount; Index++) {
        Section = &MappingEntry->FirstSection[Index];
        SectionSpan = Section->Misc.VirtualSize;
        if (Section->SizeOfRawData > SectionSpan) {
            SectionSpan = Section->SizeOfRawData;
        }
        if (Section->VirtualAddress > (MAXULONG - SectionSpan)) {
            continue;
        }

        if (Rva < Section->VirtualAddress || Rva >= (Section->VirtualAddress + SectionSpan)) {
            continue;
        }

        Delta = Rva - Section->VirtualAddress;
        if (Delta >= Section->SizeOfRawData) {
            return NULL;
        }

        if (Section->PointerToRawData > (MAXULONG - Delta)) {
            return NULL;
        }
        RawOffset = Section->PointerToRawData + Delta;
        if (RawOffset > MappingEntry->MappingSize ||
            RequiredSize > (MappingEntry->MappingSize - RawOffset)) {
            return NULL;
        }

        return (PUCHAR)MappingEntry->MappingBase + RawOffset;
    }

    // Fallback for already image-mapped input where RVA is directly valid.
    if (Rva <= MappingEntry->MappingSize &&
        RequiredSize <= (MappingEntry->MappingSize - Rva)) {
        return (PUCHAR)MappingEntry->MappingBase + Rva;
    }

    return NULL;
}

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, InitializeDriverGlobalState)
    #pragma alloc_text(INIT, InitializeSharedMemoryBuffer)
#endif

//------------------------------------------------------------------------------
// DriverMapEntry - Custom Entry Point for Manual Mapping
//
// This function serves as the alternative entry point for drivers that
// require manual mapping. It supports:
// - Custom PE header parsing
// - Manual section loading
// - Import resolution without standard Loader
// - Deferred initialization
//
// Parameters:
//   MappingBase      - Base address of the mapped driver image
//   MappingSize      - Size of the mapped image in bytes
//   DriverExtension  - Pointer to the driver extension structure
//
// Returns:
//   VOID - Initialization status stored in GlobalState
//------------------------------------------------------------------------------

VOID NTAPI DriverMapEntry(
    IN PVOID MappingBase,
    IN ULONG MappingSize,
    IN PDRIVER_EXTENSION DriverExtension
)
{
    NTSTATUS Status;
    PMANUAL_MAPPING_ENTRY MappingEntry;

    // Validate input parameters
    if (MappingBase == NULL || MappingSize == 0 || DriverExtension == NULL) {
        return;
    }

    if (!G_DriverState.Initialized) {
        // Initialize driver global state on first-use path only.
        Status = InitializeDriverGlobalState(&G_DriverState);
        if (!IS_SUCCESS(Status)) {
            G_DriverState.TotalErrors++;
            return;
        }
    }

    MappingEntry = (PMANUAL_MAPPING_ENTRY)ExAllocatePoolUninitialized(
        NonPagedPoolNx,
        sizeof(MANUAL_MAPPING_ENTRY),
        MAPPING_ENTRY_TAG
    );
    if (MappingEntry == NULL) {
        G_DriverState.TotalErrors++;
        return;
    }

    Status = CreateManualMapping(MappingEntry, MappingBase, MappingSize);
    if (!IS_SUCCESS(Status)) {
        G_DriverState.TotalValidationErrors++;
        ExFreePool(MappingEntry);
        return;
    }

    MappingEntry->MappingFlags |= MAPPING_FLAG_HEAP_ALLOCATED;
    MappingEntry->DriverExtension = DriverExtension;

    if (G_DriverState.CurrentMapping != NULL) {
        ReleaseManualMapping(G_DriverState.CurrentMapping);
    }

    // Set mapping as current
    G_DriverState.CurrentMapping = MappingEntry;
    G_DriverState.IsManuallyMapped = TRUE;

    // Initialize shared signaling
    Status = InitializeSharedSignaling(&G_DriverState);
    if (IS_SUCCESS(Status)) {
        MappingEntry->MappingFlags |= MAPPING_FLAG_INITIALIZED;
    }

    // Mark entry point as resolved
    MappingEntry->EntryPoint = DriverMapEntry;
    MappingEntry->EntryPointResolved = TRUE;
}

//------------------------------------------------------------------------------
// InitializeDriverGlobalState
//
// Initializes the driver global state structure with default values
// and prepares it for operation.
//
// Parameters:
//   GlobalState      - Pointer to the driver global state structure
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeDriverGlobalState(
    IN PDRIVER_GLOBAL_STATE GlobalState
)
{
    BOOLEAN AlreadyInitialized;

    if (GlobalState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    AlreadyInitialized = GlobalState->Initialized;
    if (AlreadyInitialized) {
        return STATUS_SUCCESS;
    }

    // Zero initialize the structure
    RtlZeroMemory(GlobalState, sizeof(DRIVER_GLOBAL_STATE));

    // Initialize driver identification
    RtlInitUnicodeString(&GlobalState->DriverName, L"StealthDriver");

    // Set driver version
    GlobalState->DriverVersion =
        (STEALTH_DRIVER_MAJOR_VERSION << 16) |
        (STEALTH_DRIVER_MINOR_VERSION << 8) |
        STEALTH_DRIVER_BUILD_NUMBER;

    // Initialize load time
    GlobalState->LoadTime = GetSystemTimeSnapshot();

    // Initialize synchronization primitive
    ExInitializePushLock(&GlobalState->GlobalLock);

    // Initialize operation counters
    GlobalState->TotalReadOperations = 0;
    GlobalState->TotalWriteOperations = 0;
    GlobalState->TotalErasureOperations = 0;
    GlobalState->TotalCommandProcessed = 0;

    // Initialize error counters
    GlobalState->TotalErrors = 0;
    GlobalState->TotalTimeouts = 0;
    GlobalState->TotalValidationErrors = 0;

    // Mark shared buffer as not initialized
    GlobalState->SharedBuffer = NULL;
    GlobalState->SharedBufferSyncContext = NULL;
    GlobalState->SharedBufferInitialized = FALSE;
    GlobalState->AccessState = DEVICE_ACCESS_REVOKED;

    // Initialize current mapping pointer
    GlobalState->CurrentMapping = NULL;
    GlobalState->IsManuallyMapped = FALSE;
    GlobalState->Initialized = TRUE;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// CleanupDriverGlobalState
//
// Cleans up resources allocated in the driver global state.
//
// Parameters:
//   GlobalState      - Pointer to the driver global state structure
//------------------------------------------------------------------------------

VOID CleanupDriverGlobalState(
    IN PDRIVER_GLOBAL_STATE GlobalState
)
{
    if (GlobalState == NULL) {
        return;
    }

    CleanupSharedSignaling(GlobalState);

    // Clean up shared buffer
    if (GlobalState->SharedBuffer != NULL) {
        ExFreePool(GlobalState->SharedBuffer);
        GlobalState->SharedBuffer = NULL;
    }
    GlobalState->SharedBufferSyncContext = NULL;
    GlobalState->SharedBufferInitialized = FALSE;

    // Clean up current mapping if present
    if (GlobalState->CurrentMapping != NULL) {
        ReleaseManualMapping(GlobalState->CurrentMapping);
        GlobalState->CurrentMapping = NULL;
    }

    // Reset counters for potential re-initialization
    GlobalState->TotalReadOperations = 0;
    GlobalState->TotalWriteOperations = 0;
    GlobalState->TotalErasureOperations = 0;
    GlobalState->TotalCommandProcessed = 0;
    GlobalState->Initialized = FALSE;
}

//------------------------------------------------------------------------------
// CreateManualMapping
//
// Creates a manual mapping entry for the specified memory region.
//
// Parameters:
//   MappingEntry     - Output pointer for the mapping entry
//   MappingBase      - Base address of the mapped region
//   MappingSize      - Size of the mapped region
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS CreateManualMapping(
    OUT PMANUAL_MAPPING_ENTRY MappingEntry,
    IN PVOID MappingBase,
    IN ULONG MappingSize
)
{
    NTSTATUS Status;
    ULONG NtOffset;
    ULONG SectionTableOffset;
    ULONG ImportRva;
    ULONG ImportSize;
    ULONG ImportCount;
    PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
    PIMAGE_IMPORT_DESCRIPTOR ImportBase;

    if (MappingEntry == NULL || MappingBase == NULL || MappingSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (MappingSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RtlZeroMemory(MappingEntry, sizeof(MANUAL_MAPPING_ENTRY));

    MappingEntry->Tag = MAPPING_ENTRY_TAG;
    MappingEntry->MappingFlags = MAPPING_FLAG_EXECUTABLE | MAPPING_FLAG_INITIALIZED;
    MappingEntry->MappingBase = MappingBase;
    MappingEntry->MappingSize = MappingSize;
    MappingEntry->LoadTime = GetSystemTimeSnapshot();
    MappingEntry->LastAccessTime = MappingEntry->LoadTime;
    MappingEntry->ReferenceCount = 1;

    // Parse PE headers
    MappingEntry->DosHeader = (PIMAGE_DOS_HEADER)MappingBase;

    if (MappingEntry->DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (MappingEntry->DosHeader->e_lfanew <= 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtOffset = (ULONG)MappingEntry->DosHeader->e_lfanew;
    if (NtOffset > MappingSize || (MappingSize - NtOffset) < sizeof(IMAGE_NT_HEADERS)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    MappingEntry->NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)MappingBase + NtOffset);

    if (MappingEntry->NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    MappingEntry->FirstSection = IMAGE_FIRST_SECTION(MappingEntry->NtHeaders);
    MappingEntry->SectionCount = MappingEntry->NtHeaders->FileHeader.NumberOfSections;
    MappingEntry->CommitSize = MappingEntry->NtHeaders->OptionalHeader.SizeOfImage;

    SectionTableOffset = (ULONG)((PUCHAR)MappingEntry->FirstSection - (PUCHAR)MappingBase);
    if (SectionTableOffset > MappingSize ||
        (MappingSize - SectionTableOffset) < (MappingEntry->SectionCount * sizeof(IMAGE_SECTION_HEADER))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Initialize imports
    ImportRva = MappingEntry->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ImportSize = MappingEntry->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (ImportSize != 0) {
        ImportBase = (PIMAGE_IMPORT_DESCRIPTOR)ResolveImagePointerFromRva(
            MappingEntry,
            ImportRva,
            sizeof(IMAGE_IMPORT_DESCRIPTOR)
        );
        if (ImportBase == NULL) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        MappingEntry->FirstImport = ImportBase;

        ImportCount = 0;
        for (ImportDesc = MappingEntry->FirstImport;
             (PUCHAR)(ImportDesc + 1) <= ((PUCHAR)MappingEntry->FirstImport + ImportSize);
             ImportDesc++) {
            if (ImportDesc->Name == 0) {
                break;
            }
            ImportCount++;
        }

        MappingEntry->ImportDescriptorCount = ImportCount;
        Status = ResolveImports(MappingEntry);
        if (IS_SUCCESS(Status) && MappingEntry->ImportDescriptorCount > 0) {
            MappingEntry->ImportsResolved = TRUE;
            MappingEntry->MappingFlags |= MAPPING_FLAG_IMPORTS_RESOLVED;
        } else if (!IS_SUCCESS(Status)) {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ReleaseManualMapping
//
// Releases resources associated with a manual mapping entry.
//
// Parameters:
//   MappingEntry     - Pointer to the mapping entry to release
//------------------------------------------------------------------------------

VOID ReleaseManualMapping(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
)
{
    LONG NewRefCount;

    if (MappingEntry == NULL) {
        return;
    }

    // Decrement reference count
    NewRefCount = InterlockedDecrement(&MappingEntry->ReferenceCount);

    if (G_DriverState.CurrentMapping == MappingEntry) {
        G_DriverState.CurrentMapping = NULL;
        G_DriverState.IsManuallyMapped = FALSE;
    }

    if (NewRefCount <= 0 && (MappingEntry->MappingFlags & MAPPING_FLAG_HEAP_ALLOCATED) != 0) {
        ExFreePool(MappingEntry);
    }
}

//------------------------------------------------------------------------------
// ResolveImports
//
// Resolves import dependencies for the manual mapping entry.
//
// Parameters:
//   MappingEntry     - Pointer to the mapping entry
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ResolveImports(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
)
{
    ULONG Index;

    if (MappingEntry == NULL || MappingEntry->FirstImport == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (Index = 0; Index < MappingEntry->ImportDescriptorCount; Index++) {
        PIMAGE_IMPORT_DESCRIPTOR ImportDesc = &MappingEntry->FirstImport[Index];

        if (ImportDesc->Name == 0) {
            break;
        }

        // Import resolution logic would be implemented here
        // This includes loading dependent modules and resolving function addresses
    }

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// IsMappingValid
//
// Validates the integrity of a manual mapping entry.
//
// Parameters:
//   MappingEntry     - Pointer to the mapping entry
//
// Returns:
//   TRUE if the mapping is valid, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN IsMappingValid(
    IN PMANUAL_MAPPING_ENTRY MappingEntry
)
{
    ULONG SectionTableOffset;

    if (MappingEntry == NULL) {
        return FALSE;
    }

    // Validate tag
    if (MappingEntry->Tag != MAPPING_ENTRY_TAG) {
        return FALSE;
    }

    // Validate mapping base and size
    if (MappingEntry->MappingBase == NULL || MappingEntry->MappingSize == 0) {
        return FALSE;
    }

    // Validate PE headers
    if (MappingEntry->DosHeader == NULL ||
        MappingEntry->DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    if (MappingEntry->NtHeaders == NULL ||
        MappingEntry->NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Validate sections
    if (MappingEntry->FirstSection == NULL || MappingEntry->SectionCount == 0) {
        return FALSE;
    }

    SectionTableOffset = (ULONG)((PUCHAR)MappingEntry->FirstSection - (PUCHAR)MappingEntry->MappingBase);
    if (SectionTableOffset > MappingEntry->MappingSize ||
        (MappingEntry->SectionCount * sizeof(IMAGE_SECTION_HEADER)) >
            (MappingEntry->MappingSize - SectionTableOffset)) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
// InitializeSharedMemoryBuffer
//
// Initializes a shared memory buffer for inter-process communication.
//
// Parameters:
//   Buffer           - Pointer to the shared memory buffer
//   BufferSize       - Size of the buffer in bytes
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeSharedMemoryBuffer(
    IN OUT PSHARED_MEMORY_BUFFER Buffer,
    IN ULONG BufferSize
)
{
    if (Buffer == NULL ||
        BufferSize < SHARED_BUFFER_MIN_SIZE ||
        BufferSize > SHARED_BUFFER_MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Buffer, sizeof(SHARED_MEMORY_BUFFER));

    Buffer->Tag = SHARED_BUFFER_TAG;
    Buffer->BufferSize = BufferSize;
    Buffer->State = COMMAND_STATUS_IDLE;
    Buffer->ReferenceCount = 1;
    Buffer->LastAccessTime = GetSystemTimeSnapshot();

    // Initialize command queue
    Buffer->QueueHead = 0;
    Buffer->QueueTail = 0;
    Buffer->QueueInitialized = TRUE;

    // Initialize buffer checksum
    Buffer->BufferChecksum = 0;

    return STATUS_SUCCESS;
}
