#pragma once

#include "TypeDefinitions.h"
#include <ntifs.h>

/**
 * @file BaseRelocation.h
 * @brief Custom base relocation processing
 *
 * Implements custom PE relocation handling to avoid standard
 * Windows loader relocations. Provides manual parsing and
 * application of relocation blocks for trace erasure.
 */

/**
 * Relocation processing statistics
 *
 * Contains information about the relocation operation including
 * original and current image bases, delta, and processing status.
 */
typedef struct _RELOCATION_STATISTICS {
    ULONGLONG OriginalImageBase;    // Original preferred image base
    ULONGLONG CurrentImageBase;     // Current mapping base address
    ULONGLONG Delta;                // Difference between bases
    ULONG RelocationCount;          // Number of relocation blocks
    BOOLEAN HasRelocations;         // Whether relocations exist
    BOOLEAN Processed;              // Processing completion status
} RELOCATION_STATISTICS, *PRELOCATION_STATISTICS;

typedef struct _RELOCATION_CONTEXT RELOCATION_CONTEXT;
typedef RELOCATION_CONTEXT* PRELOCATION_CONTEXT;

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
);

/**
 * Cleanup base relocation context
 *
 * Releases resources associated with the relocation context.
 *
 * @param pContext Pointer to the relocation context
 */
VOID NTAPI RelocationContextCleanup(
    _In_opt_ PRELOCATION_CONTEXT pContext
);

/**
 * Process base relocations
 *
 * Iterates through all relocation blocks and applies necessary
 * adjustments to accommodate the current mapping base address.
 *
 * @param pContext Pointer to the relocation context
 * @return STATUS_SUCCESS on successful processing
 */
NTSTATUS NTAPI ProcessBaseRelocations(
    _In_ PRELOCATION_CONTEXT pContext
);

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
);
