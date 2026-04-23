#include "BaseRelocation.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

/**
 * Base relocation structures for custom parsing and processing
 */

struct _RELOCATION_CONTEXT {
    PVOID MappingBase;
    ULONG MappingSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION FirstRelocation;
    ULONG RelocationDirectorySize;
    ULONG RelocationCount;
    BOOLEAN Processed;
    ULONGLONG OriginalImageBase;
    ULONGLONG CurrentImageBase;
    ULONGLONG Delta;
};

// Forward declarations
static NTSTATUS ParseRelocationDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PRELOCATION_CONTEXT pContext
);

static NTSTATUS ProcessRelocationBlocks(
    _In_ PRELOCATION_CONTEXT pContext
);

static NTSTATUS ApplyRelocation(
    _In_ PRELOCATION_CONTEXT pContext,
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ ULONG EntryCount
);

static NTSTATUS ApplyBaseRelocation(
    _In_ PRELOCATION_CONTEXT pContext,
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ USHORT EntryType,
    _In_ USHORT EntryOffset,
    _In_ ULONGLONG Delta
);

/**
 * Initialize custom base relocation parser
 *
 * Creates and initializes the relocation context with parsed
 * relocation information from the mapped driver image.
 *
 * @param MappingBase Base address of the mapped driver image
 * @param MappingSize Size of the mapped image in bytes
 * @param ImageBase Preferred image base address
 * @param ppContext Output pointer to receive initialized relocation context
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS NTAPI RelocationContextInitialize(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ ULONGLONG ImageBase,
    _Out_ PRELOCATION_CONTEXT* ppContext
)
{
    NTSTATUS status;
    PRELOCATION_CONTEXT pContext = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    ULONG ntHeadersOffset;

    if (MappingBase == NULL || ppContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate relocation context
    pContext = (PRELOCATION_CONTEXT)ExAllocatePoolUninitialized(
        NonPagedPool,
        sizeof(RELOCATION_CONTEXT),
        DRIVER_TAG
    );

    if (pContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(pContext, sizeof(RELOCATION_CONTEXT));

    // Parse DOS header
    pDosHeader = (PIMAGE_DOS_HEADER)MappingBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    // Parse NT headers
    ntHeadersOffset = pDosHeader->e_lfanew;
    if (ntHeadersOffset == 0 || ntHeadersOffset >= MappingSize) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)MappingBase + ntHeadersOffset);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    // Initialize context with header information
    pContext->MappingBase = MappingBase;
    pContext->MappingSize = MappingSize;
    pContext->NtHeaders = pNtHeaders;
    pContext->OriginalImageBase = ImageBase;
    pContext->CurrentImageBase = (ULONGLONG)MappingBase;
    pContext->Delta = pContext->CurrentImageBase - pContext->OriginalImageBase;
    pContext->Processed = FALSE;

    // Parse relocation directory
    status = ParseRelocationDirectory(MappingBase, MappingSize,
                                      pNtHeaders, pContext);

    if (NT_SUCCESS(status)) {
        *ppContext = pContext;
    }
    else {
        ExFreePool(pContext);
        *ppContext = NULL;
    }

    return status;

Cleanup:
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
    return status;
}

/**
 * Cleanup base relocation context
 *
 * Releases resources associated with the relocation context.
 *
 * @param pContext Pointer to the relocation context
 */
VOID NTAPI RelocationContextCleanup(_In_opt_ PRELOCATION_CONTEXT pContext)
{
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
}

/**
 * Process base relocations
 *
 * Iterates through all relocation blocks and applies necessary
 * adjustments to accommodate the current mapping base address.
 *
 * @param pContext Pointer to the relocation context
 * @return STATUS_SUCCESS on successful processing
 */
NTSTATUS NTAPI ProcessBaseRelocations(_In_ PRELOCATION_CONTEXT pContext)
{
    NTSTATUS status;

    if (pContext == NULL || pContext->Processed) {
        return pContext == NULL ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }

    // No relocation needed if delta is zero
    if (pContext->Delta == 0) {
        pContext->Processed = TRUE;
        return STATUS_SUCCESS;
    }

    // Process relocation blocks
    status = ProcessRelocationBlocks(pContext);

    if (NT_SUCCESS(status)) {
        pContext->Processed = TRUE;
    }

    return status;
}

/**
 * Parse relocation directory from PE image
 *
 * Locates and validates the base relocation directory, extracting
 * the relocation block chain and entry counts.
 *
 * @param MappingBase Base address of the mapped image
 * @param MappingSize Size of the mapped image
 * @param pNtHeaders Pointer to NT headers
 * @param pContext Output relocation context
 * @return STATUS_SUCCESS on successful parsing
 */
static NTSTATUS ParseRelocationDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PRELOCATION_CONTEXT pContext
)
{
    PIMAGE_DATA_DIRECTORY pRelocDir;
    PIMAGE_BASE_RELOCATION pFirstBlock;
    ULONG relocDirOffset;

    // Get relocation directory entry
    pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // Check if relocation directory exists
    if (pRelocDir->Size == 0 || pRelocDir->VirtualAddress == 0) {
        pContext->FirstRelocation = NULL;
        pContext->RelocationCount = 0;
        return STATUS_SUCCESS;
    }

    // Calculate relocation directory offset
    relocDirOffset = (ULONG)(pRelocDir->VirtualAddress);

    // Validate relocation directory bounds
    if (relocDirOffset >= MappingSize ||
        pRelocDir->Size > (MappingSize - relocDirOffset) ||
        pRelocDir->Size < sizeof(IMAGE_BASE_RELOCATION)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get first relocation block
    pFirstBlock = (PIMAGE_BASE_RELOCATION)((PUCHAR)MappingBase + relocDirOffset);

    // Count relocation blocks
    pContext->FirstRelocation = pFirstBlock;
    pContext->RelocationDirectorySize = pRelocDir->Size;
    pContext->RelocationCount = CalculateRelocationBlockCount(
        pFirstBlock,
        pRelocDir->Size
    );

    return STATUS_SUCCESS;
}

/**
 * Process relocation blocks
 *
 * Iterates through the chain of relocation blocks and applies
 * each relocation entry to the mapped image.
 *
 * @param pContext Pointer to the relocation context
 * @return STATUS_SUCCESS on successful processing
 */
static NTSTATUS ProcessRelocationBlocks(_In_ PRELOCATION_CONTEXT pContext)
{
    PIMAGE_BASE_RELOCATION pCurrentBlock;
    NTSTATUS status;
    ULONG processedBytes;
    ULONG remainingBytes;
    ULONG blockSize;
    ULONG entryCount;

    pCurrentBlock = pContext->FirstRelocation;
    processedBytes = 0;

    while (pCurrentBlock != NULL && processedBytes < pContext->RelocationDirectorySize) {
        remainingBytes = pContext->RelocationDirectorySize - processedBytes;
        if (pContext->RelocationDirectorySize < sizeof(IMAGE_BASE_RELOCATION) ||
            processedBytes > (pContext->RelocationDirectorySize - sizeof(IMAGE_BASE_RELOCATION))) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (remainingBytes < sizeof(IMAGE_BASE_RELOCATION)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        blockSize = pCurrentBlock->SizeOfBlock;
        if (blockSize == 0) {
            break;
        }

        if (blockSize < sizeof(IMAGE_BASE_RELOCATION) || blockSize > remainingBytes) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (((blockSize - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(IMAGE_RELOCANT)) != 0) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // Calculate number of entries in current block
        entryCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) /
                     sizeof(IMAGE_RELOCANT);

        // Apply relocations for current block
        status = ApplyRelocation(pContext, pCurrentBlock, entryCount);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        processedBytes += blockSize;
        pCurrentBlock = (PIMAGE_BASE_RELOCATION)((PUCHAR)pCurrentBlock + blockSize);
    }

    return STATUS_SUCCESS;
}

/**
 * Apply relocation for a single block
 *
 * Processes all relocation entries within a block, applying
 * type-specific adjustments based on the delta.
 *
 * @param pContext Pointer to the relocation context
 * @param pRelocationBlock Pointer to the relocation block
 * @param EntryCount Number of entries in the block
 * @return STATUS_SUCCESS on successful application
 */
static NTSTATUS ApplyRelocation(
    _In_ PRELOCATION_CONTEXT pContext,
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ ULONG EntryCount
)
{
    PIMAGE_RELOCANT pEntry;
    PIMAGE_RELOCANT pEndEntries;
    NTSTATUS status;

    if (EntryCount == 0) {
        return STATUS_SUCCESS;
    }

    pEntry = (PIMAGE_RELOCANT)((PUCHAR)pRelocationBlock + sizeof(IMAGE_BASE_RELOCATION));
    pEndEntries = pEntry + EntryCount;

    while (pEntry < pEndEntries) {
        // Extract entry type and offset
        USHORT entryType = (USHORT)((ULONG)(pEntry->Value) >> IMAGE_RELOCANT_OFFSET_SHIFT);
        USHORT entryOffset = (USHORT)((ULONG)(pEntry->Value) & IMAGE_RELOCANT_OFFSET_MASK);

        // Apply base relocation
        status = ApplyBaseRelocation(
            pContext,
            pRelocationBlock,
            entryType,
            entryOffset,
            pContext->Delta
        );

        if (!NT_SUCCESS(status)) {
            return status;
        }

        pEntry++;
    }

    return STATUS_SUCCESS;
}

/**
 * Apply base relocation to target address
 *
 * Calculates and applies the appropriate relocation adjustment
 * based on the entry type and delta.
 *
 * @param pRelocationBlock Pointer to the relocation block
 * @param BlockOffset Virtual address of the block
 * @param EntryType Relocation type (IMAGE_REL_xxx)
 * @param EntryOffset Offset within the block
 * @param Delta Difference between current and original base
 * @return STATUS_SUCCESS on successful application
 */
static NTSTATUS ApplyBaseRelocation(
    _In_ PRELOCATION_CONTEXT pContext,
    _In_ PIMAGE_BASE_RELOCATION pRelocationBlock,
    _In_ USHORT EntryType,
    _In_ USHORT EntryOffset,
    _In_ ULONGLONG Delta
)
{
    PVOID targetAddress;
    ULONGLONG targetRva;
    SIZE_T writeSize;

    if (pContext == NULL || pRelocationBlock == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    targetRva = (ULONGLONG)pRelocationBlock->VirtualAddress + (ULONGLONG)EntryOffset;

    switch (EntryType) {
        case IMAGE_REL_BASED_HIGHLOW:
            writeSize = sizeof(ULONG);
            break;
        case IMAGE_REL_BASED_DIR64:
            writeSize = sizeof(ULONGLONG);
            break;
        case IMAGE_REL_BASED_HIGH:
        case IMAGE_REL_BASED_LOW:
            writeSize = sizeof(USHORT);
            break;
        case IMAGE_REL_BASED_ABSOLUTE:
            return STATUS_SUCCESS;
        default:
            return STATUS_SUCCESS;
    }

    if (targetRva >= pContext->MappingSize ||
        writeSize > (SIZE_T)(pContext->MappingSize - (ULONG)targetRva)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Calculate target address within mapped image
    targetAddress = (PVOID)((PUCHAR)pContext->MappingBase + (ULONG)targetRva);

    // Apply relocation based on type
    switch (EntryType) {
        case IMAGE_REL_BASED_HIGHLOW:
            // 32-bit relocation
            *(PULONG)targetAddress = (ULONG)((ULONG)*(PULONG)targetAddress +
                                              (ULONG)Delta);
            break;

        case IMAGE_REL_BASED_DIR64:
            // 64-bit relocation
            *(PULONGLONG)targetAddress = *(PULONGLONG)targetAddress + Delta;
            break;

        case IMAGE_REL_BASED_HIGH:
            // High 16-bit relocation
            *(PUSHORT)targetAddress = (USHORT)((ULONG)*(PUSHORT)targetAddress +
                                                 (ULONG)(Delta >> 16));
            break;

        case IMAGE_REL_BASED_LOW:
            // Low 16-bit relocation
            *(PUSHORT)targetAddress = (USHORT)((ULONG)*(PUSHORT)targetAddress +
                                                 (ULONG)Delta);
            break;
    }

    return STATUS_SUCCESS;
}

/**
 * Calculate relocation block count
 *
 * Iterates through relocation blocks to determine total count.
 *
 * @param pFirstBlock Pointer to first relocation block
 * @param DirectorySize Total size of relocation directory
 * @return Number of relocation blocks
 */
ULONG CalculateRelocationBlockCount(
    _In_ PIMAGE_BASE_RELOCATION pFirstBlock,
    _In_ ULONG DirectorySize
)
{
    ULONG count = 0;
    PIMAGE_BASE_RELOCATION pCurrent;
    ULONG currentOffset = 0;

    if (pFirstBlock == NULL || DirectorySize == 0) {
        return 0;
    }

    pCurrent = pFirstBlock;

    while (currentOffset < DirectorySize &&
           pCurrent->SizeOfBlock != 0) {
        if (pCurrent->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            pCurrent->SizeOfBlock > (DirectorySize - currentOffset)) {
            break;
        }
        count++;
        currentOffset += pCurrent->SizeOfBlock;
        pCurrent = (PIMAGE_BASE_RELOCATION)((PUCHAR)pCurrent +
                                             pCurrent->SizeOfBlock);
    }

    return count;
}

/**
 * Get relocation statistics
 *
 * Retrieves detailed statistics about the relocation processing.
 *
 * @param pContext Pointer to the relocation context
 * @param pStats Output pointer to receive statistics
 * @return STATUS_SUCCESS on successful retrieval
 */
NTSTATUS NTAPI GetRelocationStatistics(
    _In_ PRELOCATION_CONTEXT pContext,
    _Out_ PRELOCATION_STATISTICS pStats
)
{
    if (pContext == NULL || pStats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlSecureZeroMemory(pStats, sizeof(RELOCATION_STATISTICS));

    pStats->OriginalImageBase = pContext->OriginalImageBase;
    pStats->CurrentImageBase = pContext->CurrentImageBase;
    pStats->Delta = pContext->Delta;
    pStats->RelocationCount = pContext->RelocationCount;
    pStats->Processed = pContext->Processed;
    pStats->HasRelocations = (pContext->FirstRelocation != NULL);

    return STATUS_SUCCESS;
}
