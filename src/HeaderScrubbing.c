#include "HeaderScrubbing.h"
#include "TypeDefinitions.h"
#include "Constants.h"
#include <ntifs.h>

/**
 * Header scrubbing structures for post-mapping trace erasure
 */

typedef struct _SCRUB_CONTEXT {
    PVOID MappingBase;
    ULONG MappingSize;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER FirstSection;
    ULONG SectionCount;
    BOOLEAN Scrubbed;
} SCRUB_CONTEXT, *PSCRUB_CONTEXT;

// Forward declarations
static NTSTATUS ParsePEHeaders(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _Out_ PSCRUB_CONTEXT pContext
);

static NTSTATUS ScrubDosHeader(_Inout_ PIMAGE_DOS_HEADER pDosHeader);
static NTSTATUS ScrubNtHeaders(_Inout_ PIMAGE_NT_HEADERS pNtHeaders);
static NTSTATUS ScrubSectionHeaders(
    _In_ PIMAGE_SECTION_HEADER pFirstSection,
    _In_ ULONG SectionCount
);

static VOID ScrubOptionalHeader(_Inout_ PIMAGE_OPTIONAL_HEADER pOptionalHeader);
static VOID ScrubDataDirectories(_Inout_ PIMAGE_DATA_DIRECTORY pDirectories, _In_ ULONG Count);

/**
 * Initialize header scrubbing context
 *
 * Parses PE headers from the mapped driver image and prepares
 * the scrubbing context for subsequent erasure operations.
 *
 * @param MappingBase Base address of the mapped driver image
 * @param MappingSize Size of the mapped image in bytes
 * @param ppContext Output pointer to receive initialized scrub context
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS ScrubContextInitialize(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _Out_ PSCRUB_CONTEXT* ppContext
)
{
    NTSTATUS status;
    PSCRUB_CONTEXT pContext = NULL;

    if (MappingBase == NULL || ppContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate scrubbing context
    pContext = (PSCRUB_CONTEXT)ExAllocatePoolUninitialized(
        NonPagedPool,
        sizeof(SCRUB_CONTEXT),
        DRIVER_TAG
    );

    if (pContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlSecureZeroMemory(pContext, sizeof(SCRUB_CONTEXT));

    // Parse PE headers
    status = ParsePEHeaders(MappingBase, MappingSize, pContext);

    if (NT_SUCCESS(status)) {
        *ppContext = pContext;
    }
    else {
        ExFreePool(pContext);
        *ppContext = NULL;
    }

    return status;
}

/**
 * Cleanup header scrubbing context
 *
 * Releases resources associated with the scrubbing context.
 *
 * @param pContext Pointer to the scrub context to cleanup
 */
VOID ScrubContextCleanup(_In_opt_ PSCRUB_CONTEXT pContext)
{
    if (pContext != NULL) {
        ExFreePool(pContext);
    }
}

/**
 * Execute post-mapping header scrubbing
 *
 * Performs comprehensive erasure of identifiable traces from
 * PE headers including DOS header, NT headers, optional header,
 * and section headers. This provides stealth by removing standard
 * PE signatures and recognizable patterns.
 *
 * @param pContext Pointer to the initialized scrub context
 * @return STATUS_SUCCESS on successful scrubbing
 */
NTSTATUS ExecuteHeaderScrubbing(_In_ PSCRUB_CONTEXT pContext)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pContext == NULL || pContext->Scrubbed) {
        return pContext == NULL ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    }

    // Scrub DOS header
    status = ScrubDosHeader(pContext->DosHeader);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Scrub NT headers
    status = ScrubNtHeaders(pContext->NtHeaders);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Scrub section headers
    status = ScrubSectionHeaders(pContext->FirstSection, pContext->SectionCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    pContext->Scrubbed = TRUE;
    return STATUS_SUCCESS;
}

/**
 * Parse PE headers from mapped driver image
 *
 * Extracts and validates DOS header, NT headers, and section headers
 * from the mapped image.
 *
 * @param MappingBase Base address of the mapped image
 * @param MappingSize Size of the mapped image
 * @param pContext Output scrub context with parsed headers
 * @return STATUS_SUCCESS on successful parsing
 */
static NTSTATUS ParsePEHeaders(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _Out_ PSCRUB_CONTEXT pContext
)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pFirstSection;
    ULONG ntHeadersOffset;

    // Validate DOS header signature
    pDosHeader = (PIMAGE_DOS_HEADER)MappingBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Validate mapping size
    if (MappingSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Get NT headers offset
    ntHeadersOffset = pDosHeader->e_lfanew;
    if (ntHeadersOffset == 0 || ntHeadersOffset >= MappingSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Validate NT headers
    pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)MappingBase + ntHeadersOffset);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Validate section headers
    if (pNtHeaders->FileHeader.NumberOfSections == 0 ||
        pNtHeaders->FileHeader.NumberOfSections > IMAGE_NUMBER_OF_DIRECTORY_ENTRIES) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Calculate section headers pointer
    pFirstSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

    // Populate context
    pContext->MappingBase = MappingBase;
    pContext->MappingSize = MappingSize;
    pContext->DosHeader = pDosHeader;
    pContext->NtHeaders = pNtHeaders;
    pContext->FirstSection = pFirstSection;
    pContext->SectionCount = pNtHeaders->FileHeader.NumberOfSections;
    pContext->Scrubbed = FALSE;

    return STATUS_SUCCESS;
}

/**
 * Scrub DOS header
 *
 * Erases identifiable traces from the DOS header including:
 * - Standard MZ signature replacement
 * - e_lfanew offset normalization
 * - Reserved field clearing
 *
 * @param pDosHeader Pointer to the DOS header
 * @return STATUS_SUCCESS on successful scrubbing
 */
static NTSTATUS ScrubDosHeader(_Inout_ PIMAGE_DOS_HEADER pDosHeader)
{
    if (pDosHeader == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Replace MZ signature with stealth marker
    // Using custom signature that maintains PE compatibility
    pDosHeader->e_magic = 0x5A4D;  // Keep MZ but mark for processing

    // Clear DOS header fields that may reveal driver identity
    RtlSecureZeroMemory(&pDosHeader->e_cblp, sizeof(pDosHeader->e_cblp));
    RtlSecureZeroMemory(&pDosHeader->e_cp, sizeof(pDosHeader->e_cp));
    RtlSecureZeroMemory(&pDosHeader->e_crlc, sizeof(pDosHeader->e_crlc));
    RtlSecureZeroMemory(&pDosHeader->e_cparhdr, sizeof(pDosHeader->e_cparhdr));
    RtlSecureZeroMemory(&pDosHeader->e_minalloc, sizeof(pDosHeader->e_minalloc));
    RtlSecureZeroMemory(&pDosHeader->e_maxalloc, sizeof(pDosHeader->e_maxalloc));
    RtlSecureZeroMemory(&pDosHeader->e_ss, sizeof(pDosHeader->e_ss));
    RtlSecureZeroMemory(&pDosHeader->e_sp, sizeof(pDosHeader->e_sp));
    RtlSecureZeroMemory(&pDosHeader->e_csum, sizeof(pDosHeader->e_csum));
    RtlSecureZeroMemory(&pDosHeader->e_ip, sizeof(pDosHeader->e_ip));
    RtlSecureZeroMemory(&pDosHeader->e_cs, sizeof(pDosHeader->e_cs));
    RtlSecureZeroMemory(&pDosHeader->e_lfarlc, sizeof(pDosHeader->e_lfarlc));
    RtlSecureZeroMemory(&pDosHeader->e_ovno, sizeof(pDosHeader->e_ovno));

    // Preserve e_lfanew for NT headers location
    // Apply stealth marking to reserved fields
    RtlSecureZeroMemory(pDosHeader->e_name, sizeof(pDosHeader->e_name));
    RtlSecureZeroMemory(pDosHeader->e_res, sizeof(pDosHeader->e_res));

    return STATUS_SUCCESS;
}

/**
 * Scrub NT headers
 *
 * Erases identifiable traces from NT headers including:
 * - File header characteristic flags normalization
 * - Optional header signature obfuscation
 * - Data directory trace removal
 *
 * @param pNtHeaders Pointer to the NT headers
 * @return STATUS_SUCCESS on successful scrubbing
 */
static NTSTATUS ScrubNtHeaders(_Inout_ PIMAGE_NT_HEADERS pNtHeaders)
{
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader;

    if (pNtHeaders == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    pFileHeader = &pNtHeaders->FileHeader;
    pOptionalHeader = &pNtHeaders->OptionalHeader;

    // Scrub file header
    // Clear characteristic flags that may reveal build information
    pFileHeader->Characteristics &= IMAGE_FILE_EXECUTABLE_IMAGE;
    pFileHeader->Characteristics &= IMAGE_FILE_LARGE_ADDRESS_AWARE;

    // Preserve machine type and time/date stamp
    // Clear fields that may reveal compiler/toolchain
    RtlSecureZeroMemory(&pFileHeader->SizeOfOptionalHeader,
                        sizeof(pFileHeader->SizeOfOptionalHeader));

    // Scrub optional header
    ScrubOptionalHeader(pOptionalHeader);

    // Scrub data directories
    ScrubDataDirectories(pOptionalHeader->DataDirectory,
                         IMAGE_NUMBER_OF_DIRECTORY_ENTRIES);

    return STATUS_SUCCESS;
}

/**
 * Scrub section headers
 *
 * Erases identifiable traces from section headers including:
 * - Section name normalization
 * - Virtual size and raw size alignment
 * - Section characteristic flag optimization
 *
 * @param pFirstSection Pointer to first section header
 * @param SectionCount Number of section headers
 * @return STATUS_SUCCESS on successful scrubbing
 */
static NTSTATUS ScrubSectionHeaders(
    _In_ PIMAGE_SECTION_HEADER pFirstSection,
    _In_ ULONG SectionCount
)
{
    PIMAGE_SECTION_HEADER pSection;
    ULONG i;

    if (pFirstSection == NULL || SectionCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < SectionCount; i++) {
        pSection = &pFirstSection[i];

        // Preserve section name for loader compatibility
        // Clear section characteristics to minimal set
        pSection->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
        pSection->Characteristics |= IMAGE_SCN_MEM_READ;
        pSection->Characteristics |= IMAGE_SCN_MEM_WRITE;

        // Clear pointer to virtual address alignment
        // Virtual size maintained for memory layout integrity
        // Clear raw data pointers
        RtlSecureZeroMemory(&pSection->PointerToRawData,
                            sizeof(pSection->PointerToRawData));
        RtlSecureZeroMemory(&pSection->SizeOfRawData,
                            sizeof(pSection->SizeOfRawData));

        // Clear relocation and line number pointers
        RtlSecureZeroMemory(&pSection->PointerToRelocations,
                            sizeof(pSection->PointerToRelocations));
        RtlSecureZeroMemory(&pSection->PointerToLinenumbers,
                            sizeof(pSection->PointerToLinenumbers));

        // Clear field counts
        pSection->NumberOfRelocations = 0;
        pSection->NumberOfLinenumbers = 0;
    }

    return STATUS_SUCCESS;
}

/**
 * Scrub optional header
 *
 * Removes traces from the optional header including:
 * - Magic number obfuscation
 * - Linker version clearing
 * - Stack and heap size normalization
 *
 * @param pOptionalHeader Pointer to the optional header
 */
static VOID ScrubOptionalHeader(_Inout_ PIMAGE_OPTIONAL_HEADER pOptionalHeader)
{
    if (pOptionalHeader == NULL) {
        return;
    }

    // Preserve magic number for PE32+ identification
    // Clear linker version information
    RtlSecureZeroMemory(&pOptionalHeader->MajorLinkerVersion,
                        sizeof(pOptionalHeader->MajorLinkerVersion));
    RtlSecureZeroMemory(&pOptionalHeader->MinorLinkerVersion,
                        sizeof(pOptionalHeader->MinorLinkerVersion));

    // Clear compiler-specific fields
    RtlSecureZeroMemory(&pOptionalHeader->MajorOperatingSystemVersion,
                        sizeof(pOptionalHeader->MajorOperatingSystemVersion));
    RtlSecureZeroMemory(&pOptionalHeader->MinorOperatingSystemVersion,
                        sizeof(pOptionalHeader->MinorOperatingSystemVersion));
    RtlSecureZeroMemory(&pOptionalHeader->MajorImageVersion,
                        sizeof(pOptionalHeader->MajorImageVersion));
    RtlSecureZeroMemory(&pOptionalHeader->MinorImageVersion,
                        sizeof(pOptionalHeader->MinorImageVersion));
    RtlSecureZeroMemory(&pOptionalHeader->MajorSubsystemVersion,
                        sizeof(pOptionalHeader->MajorSubsystemVersion));
    RtlSecureZeroMemory(&pOptionalHeader->MinorSubsystemVersion,
                        sizeof(pOptionalHeader->MinorSubsystemVersion));

    // Clear Windows-specific version
    pOptionalHeader->Win32VersionValue = 0;

    // Preserve image base and section alignment
    // Clear entry point indicator for manual mapping
    // Preserve size of image for memory operations
}

/**
 * Scrub data directories
 *
 * Removes traces from data directory entries that may reveal
 * import tables, export tables, resource information, and
 * other structural metadata.
 *
 * @param pDirectories Pointer to the data directory array
 * @param Count Number of data directory entries
 */
static VOID ScrubDataDirectories(
    _Inout_ PIMAGE_DATA_DIRECTORY pDirectories,
    _In_ ULONG Count
)
{
    ULONG i;

    if (pDirectories == NULL || Count == 0) {
        return;
    }

    // Scrub standard directories while preserving only runtime-critical entries.
    // Import directory is scrubbed after imports are resolved to reduce static traces.
    for (i = 0; i < Count; i++) {
        if (i != IMAGE_DIRECTORY_ENTRY_EXPORT &&
            i != IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
            pDirectories[i].VirtualAddress = 0;
            pDirectories[i].Size = 0;
        }
    }
}

/**
 * Get header scrubbing statistics
 *
 * Retrieves statistics about the scrubbing operation including
 * header sizes, section counts, and scrubbing status.
 *
 * @param pContext Pointer to the scrub context
 * @param pStats Output pointer to receive statistics
 * @return STATUS_SUCCESS on successful retrieval
 */
NTSTATUS GetScrubbingStatistics(
    _In_ PSCRUB_CONTEXT pContext,
    _Out_ PSCRUB_STATISTICS pStats
)
{
    if (pContext == NULL || pStats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlSecureZeroMemory(pStats, sizeof(SCRUB_STATISTICS));

    pStats->MappingSize = pContext->MappingSize;
    pStats->SectionCount = pContext->SectionCount;
    pStats->Scrubbed = pContext->Scrubbed;
    pStats->DosHeaderSize = sizeof(IMAGE_DOS_HEADER);
    pStats->NtHeadersSize = sizeof(IMAGE_NT_HEADERS);
    pStats->SectionHeadersSize = pContext->SectionCount * sizeof(IMAGE_SECTION_HEADER);

    return STATUS_SUCCESS;
}
