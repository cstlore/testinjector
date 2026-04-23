#include "ImportTable.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

/**
 * Import table processing structures for custom resolution
 */

struct _IMPORT_CONTEXT {
    PVOID MappingBase;
    ULONG MappingSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DATA_DIRECTORY ImportDir;
    PIMAGE_IMPORT_DESCRIPTOR FirstDescriptor;
    ULONG DescriptorCount;
    BOOLEAN Processed;
    BOOLEAN CustomResolved;
};

static BOOLEAN IsRangeWithinMapping(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ ULONGLONG Offset,
    _In_ SIZE_T Size
);

// Forward declarations
static NTSTATUS ParseImportDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PIMPORT_CONTEXT pContext
);

static NTSTATUS ProcessImportDescriptors(
    _In_ PIMPORT_CONTEXT pContext
);

static NTSTATUS ResolveImportDescriptor(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor
);

static NTSTATUS ResolveImportByName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ PCCH ImportName,
    _In_ PCCH FunctionName
);

static NTSTATUS ResolveImportByOrdinal(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ ULONG Ordinal
);

static PVOID LocateImportData(
    _In_ PIMAGE_THUNK_DATA pThunk,
    _In_ BOOLEAN IsOriginal
);

static ULONG CalculateDescriptorCount(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pFirstDescriptor,
    _In_ ULONG ImportDirSize
);

static PCCH GetImportLibraryName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor
);

static PCCH GetImportFunctionName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk
);

/**
 * Initialize import table processing context
 *
 * Creates and initializes the import context with parsed
 * import directory information from the mapped driver image.
 *
 * @param MappingBase Base address of the mapped driver image
 * @param MappingSize Size of the mapped image in bytes
 * @param ppContext Output pointer to receive initialized import context
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS NTAPI ImportContextInitialize(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _Out_ PIMPORT_CONTEXT* ppContext
)
{
    NTSTATUS status;
    PIMPORT_CONTEXT pContext = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    ULONG ntHeadersOffset;

    if (MappingBase == NULL || ppContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate import context
    pContext = (PIMPORT_CONTEXT)ExAllocatePoolUninitialized(
        NonPagedPool,
        sizeof(IMPORT_CONTEXT),
        DRIVER_TAG
    );

    if (pContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(pContext, sizeof(IMPORT_CONTEXT));

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
    pContext->Processed = FALSE;
    pContext->CustomResolved = FALSE;

    // Parse import directory
    status = ParseImportDirectory(MappingBase, MappingSize,
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
 * Cleanup import table processing context
 *
 * Releases resources associated with the import context.
 *
 * @param pContext Pointer to the import context
 */
VOID NTAPI ImportContextCleanup(_In_opt_ PIMPORT_CONTEXT pContext)
{
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
}

/**
 * Process import table
 *
 * Iterates through all import descriptors and resolves
 * imported functions using custom resolution mechanisms.
 *
 * @param pContext Pointer to the import context
 * @return STATUS_SUCCESS on successful processing
 */
NTSTATUS NTAPI ProcessImportTable(_In_ PIMPORT_CONTEXT pContext)
{
    NTSTATUS status;

    if (pContext == NULL || pContext->Processed) {
        return pContext == NULL ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }

    // Process import descriptors
    status = ProcessImportDescriptors(pContext);

    if (NT_SUCCESS(status)) {
        pContext->Processed = TRUE;
        pContext->CustomResolved = TRUE;
    }

    return status;
}

/**
 * Parse import directory from PE image
 *
 * Locates and validates the import directory, extracting
 * the descriptor chain and import information.
 *
 * @param MappingBase Base address of the mapped image
 * @param MappingSize Size of the mapped image
 * @param pNtHeaders Pointer to NT headers
 * @param pContext Output import context
 * @return STATUS_SUCCESS on successful parsing
 */
static NTSTATUS ParseImportDirectory(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _Out_ PIMPORT_CONTEXT pContext
)
{
    PIMAGE_DATA_DIRECTORY pImportDir;
    PIMAGE_IMPORT_DESCRIPTOR pFirstDescriptor;
    ULONG importDirOffset;
    ULONG descriptorCount;

    // Get import directory entry
    pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Check if import directory exists
    if (pImportDir->Size == 0 || pImportDir->VirtualAddress == 0) {
        pContext->FirstDescriptor = NULL;
        pContext->DescriptorCount = 0;
        return STATUS_SUCCESS;
    }

    // Calculate import directory offset
    importDirOffset = (ULONG)(pImportDir->VirtualAddress);

    // Validate import directory bounds
    if (importDirOffset >= MappingSize ||
        pImportDir->Size > (MappingSize - importDirOffset) ||
        pImportDir->Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get first import descriptor
    pFirstDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)MappingBase + importDirOffset);

    // Store import directory information
    pContext->ImportDir = pImportDir;
    pContext->FirstDescriptor = pFirstDescriptor;

    // Count import descriptors with directory bounds validation.
    descriptorCount = CalculateDescriptorCount(pContext, pFirstDescriptor, pImportDir->Size);
    if (descriptorCount == 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    pContext->DescriptorCount = descriptorCount;

    return STATUS_SUCCESS;
}

/**
 * Process import descriptors
 *
 * Iterates through the chain of import descriptors and resolves
 * each imported function.
 *
 * @param pContext Pointer to the import context
 * @return STATUS_SUCCESS on successful processing
 */
static NTSTATUS ProcessImportDescriptors(_In_ PIMPORT_CONTEXT pContext)
{
    PIMAGE_IMPORT_DESCRIPTOR pCurrentDescriptor;
    NTSTATUS status;
    ULONG i;

    pCurrentDescriptor = pContext->FirstDescriptor;

    // Process descriptors bounded by parsed descriptor count.
    for (i = 0; i < pContext->DescriptorCount; i++) {
        // Resolve current import descriptor
        status = ResolveImportDescriptor(pContext, pCurrentDescriptor);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        pCurrentDescriptor++;
    }

    return STATUS_SUCCESS;
}

/**
 * Resolve a single import descriptor
 *
 * Processes all imported functions within a descriptor,
 * resolving both name-based and ordinal-based imports.
 *
 * @param pContext Pointer to the import context
 * @param pDescriptor Pointer to the import descriptor
 * @return STATUS_SUCCESS on successful resolution
 */
static NTSTATUS ResolveImportDescriptor(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor
)
{
    PIMAGE_THUNK_DATA pOriginalThunk;
    PIMAGE_THUNK_DATA pCurrentOriginal;
    NTSTATUS status;
    ULONG maxThunkEntries;
    ULONG i;
    ULONGLONG originalThunkOffset;

    if (pDescriptor->OriginalFirstThunk == 0 ||
        pDescriptor->FirstThunk == 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    originalThunkOffset = (ULONGLONG)pDescriptor->OriginalFirstThunk;
    if (!IsRangeWithinMapping(pContext, originalThunkOffset, sizeof(IMAGE_THUNK_DATA))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    pOriginalThunk = (PIMAGE_THUNK_DATA)((PUCHAR)pContext->MappingBase +
                                          pDescriptor->OriginalFirstThunk);
    maxThunkEntries = (ULONG)((pContext->MappingSize - (ULONG)originalThunkOffset) /
                              sizeof(IMAGE_THUNK_DATA));
    if (maxThunkEntries == 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Process each import thunk
    pCurrentOriginal = pOriginalThunk;

    for (i = 0; i < maxThunkEntries && pCurrentOriginal->AddressOfData != 0; i++) {
        BOOLEAN isOrdinal = FALSE;
        ULONG ordinal = 0;
        PCCH importName = NULL;
        PCCH functionName = NULL;

        // Determine if import is by ordinal or name
        if (IMAGE_SNAP_BY_ORDINAL(pCurrentOriginal->u1.Ordinal)) {
            isOrdinal = TRUE;
            ordinal = (ULONG)IMAGE_ORDINAL(pCurrentOriginal->u1.Ordinal);
        }
        else {
            // Resolve import by name
            importName = GetImportLibraryName(pContext, pDescriptor);
            functionName = GetImportFunctionName(pContext, pCurrentOriginal);
            if (importName == NULL || functionName == NULL) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        // Resolve import based on type
        if (isOrdinal) {
            status = ResolveImportByOrdinal(pContext, pDescriptor,
                                            pCurrentOriginal, ordinal);
        }
        else {
            status = ResolveImportByName(pContext, pDescriptor,
                                         pCurrentOriginal, importName, functionName);
        }

        if (!NT_SUCCESS(status)) {
            return status;
        }

        pCurrentOriginal++;
    }

    if (i == maxThunkEntries) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

/**
 * Resolve import by function name
 *
 * Resolves an imported function using the library and function names.
 *
 * @param pContext Pointer to the import context
 * @param pDescriptor Pointer to the import descriptor
 * @param pOriginalThunk Pointer to the original thunk
 * @param ImportName Name of the import library
 * @param FunctionName Name of the imported function
 * @return STATUS_SUCCESS on successful resolution
 */
static NTSTATUS ResolveImportByName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ PCCH ImportName,
    _In_ PCCH FunctionName
)
{
    // Placeholder for custom name-based resolution
    // In a complete implementation, this would resolve the function
    // address and update the thunk with the resolved address

    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(pDescriptor);
    UNREFERENCED_PARAMETER(pOriginalThunk);
    UNREFERENCED_PARAMETER(ImportName);
    UNREFERENCED_PARAMETER(FunctionName);

    return STATUS_SUCCESS;
}

/**
 * Resolve import by ordinal
 *
 * Resolves an imported function using the ordinal value.
 *
 * @param pContext Pointer to the import context
 * @param pDescriptor Pointer to the import descriptor
 * @param pOriginalThunk Pointer to the original thunk
 * @param Ordinal Ordinal value of the imported function
 * @return STATUS_SUCCESS on successful resolution
 */
static NTSTATUS ResolveImportByOrdinal(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk,
    _In_ ULONG Ordinal
)
{
    // Placeholder for custom ordinal-based resolution
    // In a complete implementation, this would resolve the function
    // address using the ordinal and update the thunk

    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(pDescriptor);
    UNREFERENCED_PARAMETER(pOriginalThunk);
    UNREFERENCED_PARAMETER(Ordinal);

    return STATUS_SUCCESS;
}

/**
 * Locate import data from thunk
 *
 * Extracts the appropriate data from a thunk based on whether
 * it's the original or bound thunk.
 *
 * @param pThunk Pointer to the thunk
 * @param IsOriginal TRUE if original thunk, FALSE if bound
 * @return Pointer to the located data
 */
static PVOID LocateImportData(
    _In_ PIMAGE_THUNK_DATA pThunk,
    _In_ BOOLEAN IsOriginal
)
{
    if (pThunk == NULL) {
        return NULL;
    }

    if (IsOriginal) {
        return (PVOID)pThunk->AddressOfData;
    }
    else {
        return (PVOID)pThunk->u1.Address;
    }
}

/**
 * Calculate import descriptor count
 *
 * Iterates through import descriptors to determine total count.
 *
 * @param pFirstDescriptor Pointer to first import descriptor
 * @return Number of import descriptors
 */
static ULONG CalculateDescriptorCount(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pFirstDescriptor,
    _In_ ULONG ImportDirSize
)
{
    ULONG count = 0;
    ULONG maxDescriptors;
    PIMAGE_IMPORT_DESCRIPTOR pCurrent;

    if (pContext == NULL || pFirstDescriptor == NULL || ImportDirSize == 0) {
        return 0;
    }

    maxDescriptors = ImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (maxDescriptors == 0) {
        return 0;
    }

    pCurrent = pFirstDescriptor;

    // Count descriptors until null terminator, bounded by import directory size.
    while (count < maxDescriptors) {
        if (!IsRangeWithinMapping(
                pContext,
                (ULONGLONG)((PUCHAR)pCurrent - (PUCHAR)pContext->MappingBase),
                sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return 0;
        }

        if (pCurrent->Name == 0 &&
            pCurrent->FirstThunk == 0 &&
            pCurrent->OriginalFirstThunk == 0) {
            break;
        }

        count++;
        pCurrent++;
    }

    // Missing null-terminator inside declared import directory.
    if (count == maxDescriptors) {
        return 0;
    }

    return count;
}

/**
 * Get import library name
 *
 * Retrieves the name of the imported library from a descriptor.
 *
 * @param pDescriptor Pointer to the import descriptor
 * @return Pointer to the library name string
 */
static PCCH GetImportLibraryName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_IMPORT_DESCRIPTOR pDescriptor
)
{
    ULONGLONG nameOffset;

    if (pContext == NULL || pDescriptor == NULL || pDescriptor->Name == 0) {
        return NULL;
    }

    nameOffset = (ULONGLONG)pDescriptor->Name;
    if (!IsRangeWithinMapping(pContext, nameOffset, sizeof(CHAR))) {
        return NULL;
    }

    return (PCCH)((PUCHAR)pContext->MappingBase + (ULONG)nameOffset);
}

/**
 * Get import function name
 *
 * Retrieves the name of an imported function from a thunk.
 *
 * @param pOriginalThunk Pointer to the original thunk
 * @return Pointer to the function name string
 */
static PCCH GetImportFunctionName(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ PIMAGE_THUNK_DATA pOriginalThunk
)
{
    PIMAGE_IMPORT_BY_NAME pImportByName;
    ULONGLONG importByNameOffset;

    if (pContext == NULL || pOriginalThunk == NULL ||
        IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
        return NULL;
    }

    importByNameOffset = (ULONGLONG)pOriginalThunk->u1.AddressOfData;
    if (!IsRangeWithinMapping(
            pContext,
            importByNameOffset,
            sizeof(IMAGE_IMPORT_BY_NAME))) {
        return NULL;
    }

    pImportByName = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)pContext->MappingBase +
                                             (ULONG)importByNameOffset);

    return (PCCH)pImportByName->Name;
}

static BOOLEAN IsRangeWithinMapping(
    _In_ PIMPORT_CONTEXT pContext,
    _In_ ULONGLONG Offset,
    _In_ SIZE_T Size
)
{
    if (pContext == NULL || Size == 0) {
        return FALSE;
    }

    if (Offset >= pContext->MappingSize) {
        return FALSE;
    }

    if (Size > (SIZE_T)(pContext->MappingSize - (ULONG)Offset)) {
        return FALSE;
    }

    return TRUE;
}

/**
 * Get import table statistics
 *
 * Retrieves detailed statistics about the import table processing.
 *
 * @param pContext Pointer to the import context
 * @param pStats Output pointer to receive statistics
 * @return STATUS_SUCCESS on successful retrieval
 */
NTSTATUS NTAPI GetImportTableStatistics(
    _In_ PIMPORT_CONTEXT pContext,
    _Out_ PIMPORT_STATISTICS pStats
)
{
    if (pContext == NULL || pStats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlSecureZeroMemory(pStats, sizeof(IMPORT_STATISTICS));

    pStats->DescriptorCount = pContext->DescriptorCount;
    pStats->Processed = pContext->Processed;
    pStats->CustomResolved = pContext->CustomResolved;
    pStats->HasImports = (pContext->FirstDescriptor != NULL);

    return STATUS_SUCCESS;
}
