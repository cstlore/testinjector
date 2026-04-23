#pragma once

#include "TypeDefinitions.h"
#include <ntifs.h>

/**
 * @file HeaderScrubbing.h
 * @brief Post-mapping header scrubbing for trace erasure
 *
 * Implements comprehensive scrubbing routines for PE headers after
 * manual mapping. Removes standard signatures and identifiable traces
 * to reduce detection surface while maintaining image integrity.
 */

// Forward declaration
typedef struct _SCRUB_CONTEXT SCRUB_CONTEXT;
typedef SCRUB_CONTEXT* PSCRUB_CONTEXT;

/**
 * Header scrubbing statistics
 *
 * Contains information about the scrubbing operation and
 * the processed headers.
 */
typedef struct _SCRUB_STATISTICS {
    ULONG MappingSize;              // Total size of mapped image
    ULONG SectionCount;             // Number of section headers
    BOOLEAN Scrubbed;               // Scrubbing completion status
    ULONG DosHeaderSize;            // Size of DOS header
    ULONG NtHeadersSize;            // Size of NT headers
    ULONG SectionHeadersSize;       // Total size of section headers
} SCRUB_STATISTICS, *PSCRUB_STATISTICS;

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
NTSTATUS NTAPI ScrubContextInitialize(
    _In_ PVOID MappingBase,
    _In_ ULONG MappingSize,
    _Out_ PSCRUB_CONTEXT* ppContext
);

/**
 * Cleanup header scrubbing context
 *
 * Releases resources associated with the scrubbing context.
 *
 * @param pContext Pointer to the scrub context to cleanup
 */
VOID NTAPI ScrubContextCleanup(
    _In_opt_ PSCRUB_CONTEXT pContext
);

/**
 * Execute post-mapping header scrubbing
 *
 * Performs comprehensive erasure of identifiable traces from
 * PE headers including DOS header, NT headers, optional header,
 * and section headers.
 *
 * @param pContext Pointer to the initialized scrub context
 * @return STATUS_SUCCESS on successful scrubbing
 */
NTSTATUS NTAPI ExecuteHeaderScrubbing(
    _In_ PSCRUB_CONTEXT pContext
);

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
NTSTATUS NTAPI GetScrubbingStatistics(
    _In_ PSCRUB_CONTEXT pContext,
    _Out_ PSCRUB_STATISTICS pStats
);