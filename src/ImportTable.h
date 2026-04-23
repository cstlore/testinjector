#pragma once

#include "TypeDefinitions.h"
#include <ntifs.h>

/**
 * @file ImportTable.h
 * @brief Custom import table processing
 *
 * Implements custom PE import table handling to avoid
 * standard Windows loader import resolution. Provides
 * manual parsing and resolution of imported functions.
 */

/**
 * Import table processing statistics
 *
 * Contains information about the import processing including
 * descriptor counts, processing status, and resolution state.
 */
typedef struct _IMPORT_STATISTICS {
    ULONG DescriptorCount;      // Number of import descriptors
    BOOLEAN HasImports;         // Whether imports exist
    BOOLEAN Processed;          // Processing completion status
    BOOLEAN CustomResolved;     // Custom resolution status
} IMPORT_STATISTICS, *PIMPORT_STATISTICS;

typedef struct _IMPORT_CONTEXT IMPORT_CONTEXT;
typedef IMPORT_CONTEXT* PIMPORT_CONTEXT;

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
);

/**
 * Cleanup import table processing context
 *
 * Releases resources associated with the import context.
 *
 * @param pContext Pointer to the import context
 */
VOID NTAPI ImportContextCleanup(
    _In_opt_ PIMPORT_CONTEXT pContext
);

/**
 * Process import table
 *
 * Iterates through all import descriptors and resolves
 * imported functions using custom resolution mechanisms.
 *
 * @param pContext Pointer to the import context
 * @return STATUS_SUCCESS on successful processing
 */
NTSTATUS NTAPI ProcessImportTable(
    _In_ PIMPORT_CONTEXT pContext
);

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
);
