/*
 * Memory Operations - Implementation
 *
 * Implements core memory operations (read, write, query, protect) with
 * manual mapping support for the stealth kernel driver.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include <ntifs.h>
#include <wdfdrivr.h>
#include "Constants.h"
#include "TypeDefinitions.h"

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

NTSYSAPI
NTSTATUS
NTAPI
ZwFlushInstructionCache(
    _In_opt_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytesToFlush
);

//------------------------------------------------------------------------------
// Internal Function Prototypes
//------------------------------------------------------------------------------

static NTSTATUS
InitializeMemoryOperationResult(
    OUT PMEMORY_OPERATION_RESULT Result,
    IN MEMORY_OPERATION OperationType,
    IN ULONGLONG TargetAddress,
    IN ULONG RequestedSize
);

static NTSTATUS
ValidateMemoryAddress(
    IN HANDLE ProcessHandle,
    IN ULONGLONG Address,
    IN ULONG Size,
    OUT PBOOLEAN IsValid
);

static NTSTATUS
CalculateMemoryChecksum(
    IN PVOID Buffer,
    IN ULONG BufferSize,
    IN ULONG Algorithm,
    OUT PULONG Checksum
);

static NTSTATUS
MapVirtualMemoryRegion(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    IN ULONG RegionSize,
    OUT PMEMORY_REGION_DESCRIPTOR RegionDescriptor
);

static NTSTATUS
ReadVirtual(
    IN HANDLE ProcessHandle,
    IN PVOID Address,
    OUT PVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesRead
);

static NTSTATUS
WriteVirtual(
    IN HANDLE ProcessHandle,
    IN PVOID Address,
    IN PCVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesWritten
);

static NTSTATUS
ResolveProcessObject(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PEPROCESS* ProcessObject
);

//------------------------------------------------------------------------------
// Memory Read Operations
//------------------------------------------------------------------------------

NTSTATUS
MemoryOperationRead(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    IN OUT PVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesRead,
    OUT PMEMORY_OPERATION_RESULT Result OPTIONAL
)
/*++
Routine Description:
    Reads memory from a target process at the specified address.

Arguments:
    ProcessHandle - Handle to the target process.
    BaseAddress - Base address to read from.
    Buffer - Buffer to receive the read data.
    BufferSize - Size of the buffer.
    BytesRead - Returns the number of bytes actually read.
    Result - Optional result structure with operation details.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    MEMORY_OPERATION_RESULT LocalResult;
    PMEMORY_OPERATION_RESULT OperationResult = Result ? Result : &LocalResult;
    BOOLEAN AddressValid = FALSE;
    ULONG ChecksumValue = 0;
    LARGE_INTEGER PerfFreq;

    // Initialize the operation result structure
    Status = InitializeMemoryOperationResult(
        OperationResult,
        MemoryOperationRead,
        BaseAddress,
        BufferSize
    );

    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    // Validate the memory address
    Status = ValidateMemoryAddress(
        ProcessHandle,
        BaseAddress,
        BufferSize,
        &AddressValid
    );

    if (!IS_SUCCESS(Status) || !AddressValid) {
        OperationResult->Status = Status;
        OperationResult->CompletedSize = 0;
        if (BytesRead) {
            *BytesRead = 0;
        }
        return Status;
    }

    // Record start time
    OperationResult->StartTime = KeQueryPerformanceCounter(NULL);

    // Perform the read operation
    Status = ReadVirtual(
        ProcessHandle,
        (PVOID)(ULONG64)BaseAddress,
        Buffer,
        BufferSize,
        BytesRead
    );

    // Record end time and calculate duration
    OperationResult->EndTime = KeQueryPerformanceCounter(NULL);
    KeQueryPerformanceCounter(&PerfFreq);
    OperationResult->DurationMicroseconds = (ULONG)(
        (OperationResult->EndTime.QuadPart - OperationResult->StartTime.QuadPart) * 1000000UL /
        (PerfFreq.QuadPart == 0 ? 1 : PerfFreq.QuadPart)
    );

    if (IS_SUCCESS(Status)) {
        OperationResult->Status = STATUS_SUCCESS;
        OperationResult->CompletedSize = *BytesRead;

        // Calculate checksum for the read data
        if (*BytesRead > 0) {
            CalculateMemoryChecksum(
                Buffer,
                *BytesRead,
                DEFAULT_CHECKSUM_ALGORITHM,
                &ChecksumValue
            );
            OperationResult->BufferChecksum = ChecksumValue;
        }
    }
    else {
        OperationResult->Status = Status;
        OperationResult->CompletedSize = 0;
        if (BytesRead) {
            *BytesRead = 0;
        }
    }

    return Status;
}

NTSTATUS
MemoryOperationReadWithMapping(
    IN PMANUAL_MAPPING_ENTRY MappingEntry,
    IN ULONGLONG RelativeAddress,
    OUT PVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesRead
)
/*++
Routine Description:
    Reads memory from a manually mapped module at the specified relative address.

Arguments:
    MappingEntry - Manual mapping entry containing module information.
    RelativeAddress - Relative address within the mapped module.
    Buffer - Buffer to receive the read data.
    BufferSize - Size of the buffer.
    BytesRead - Returns the number of bytes actually read.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    PVOID SourceAddress;
    ULONG AvailableSize;

    // Validate the mapping entry
    if (MappingEntry == NULL ||
        MappingEntry->MappingBase == NULL ||
        MappingEntry->MappingSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calculate the source address within the mapping
    SourceAddress = (PCHAR)MappingEntry->MappingBase + RelativeAddress;

    // Verify the address is within the mapping bounds
    if (RelativeAddress >= MappingEntry->MappingSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Calculate available size from the relative address
    AvailableSize = (ULONG)(MappingEntry->MappingSize - RelativeAddress);
    if (BufferSize > AvailableSize) {
        BufferSize = AvailableSize;
    }

    // Perform the read operation with bounds checking
    if (MappingEntry->DosHeader && MappingEntry->DosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        // Module is a valid PE image - perform section-aware read
        PIMAGE_SECTION_HEADER CurrentSection;
        ULONG i;

        CurrentSection = MappingEntry->FirstSection;

        for (i = 0; i < MappingEntry->SectionCount; i++) {
            ULONGLONG SectionStart = CurrentSection->VirtualAddress;
            ULONGLONG SectionEnd = SectionStart + CurrentSection->Misc.VirtualSize;

            if (RelativeAddress >= SectionStart &&
                RelativeAddress < SectionEnd) {
                // Address is within this section
                ULONG SectionOffset = (ULONG)(RelativeAddress - SectionStart);

                if (CurrentSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
                    // Read from initialized data section
                    PCHAR SectionData = (PCHAR)MappingEntry->MappingBase +
                        CurrentSection->VirtualAddress;

                    RtlMoveMemory(
                        Buffer,
                        SectionData + SectionOffset,
                        BufferSize
                    );

                    if (BytesRead) {
                        *BytesRead = BufferSize;
                    }

                    Status = STATUS_SUCCESS;
                    break;
                }
                else if (CurrentSection->Characteristics & IMAGE_SCN_CNT_CODE) {
                    // Read from code section
                    PCHAR SectionData = (PCHAR)MappingEntry->MappingBase +
                        CurrentSection->VirtualAddress;

                    RtlMoveMemory(
                        Buffer,
                        SectionData + SectionOffset,
                        BufferSize
                    );

                    if (BytesRead) {
                        *BytesRead = BufferSize;
                    }

                    Status = STATUS_SUCCESS;
                    break;
                }
            }

            CurrentSection++;
        }

        if (!IS_SUCCESS(Status)) {
            return STATUS_SECTION_NOT_FOUND;
        }
    }
    else {
        // Fallback to direct memory copy
        RtlMoveMemory(Buffer, SourceAddress, BufferSize);

        if (BytesRead) {
            *BytesRead = BufferSize;
        }

        Status = STATUS_SUCCESS;
    }

    return Status;
}

//------------------------------------------------------------------------------
// Memory Write Operations
//------------------------------------------------------------------------------

NTSTATUS
MemoryOperationWrite(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    IN PCVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesWritten,
    OUT PMEMORY_OPERATION_RESULT Result OPTIONAL
)
/*++
Routine Description:
    Writes memory to a target process at the specified address.

Arguments:
    ProcessHandle - Handle to the target process.
    BaseAddress - Base address to write to.
    Buffer - Buffer containing the data to write.
    BufferSize - Size of the buffer.
    BytesWritten - Returns the number of bytes actually written.
    Result - Optional result structure with operation details.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    MEMORY_OPERATION_RESULT LocalResult;
    PMEMORY_OPERATION_RESULT OperationResult = Result ? Result : &LocalResult;
    BOOLEAN AddressValid = FALSE;
    LARGE_INTEGER PerfFreq;

    // Initialize the operation result structure
    Status = InitializeMemoryOperationResult(
        OperationResult,
        MemoryOperationWrite,
        BaseAddress,
        BufferSize
    );

    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    // Validate the memory address
    Status = ValidateMemoryAddress(
        ProcessHandle,
        BaseAddress,
        BufferSize,
        &AddressValid
    );

    if (!IS_SUCCESS(Status) || !AddressValid) {
        OperationResult->Status = Status;
        OperationResult->CompletedSize = 0;
        if (BytesWritten) {
            *BytesWritten = 0;
        }
        return Status;
    }

    // Record start time
    OperationResult->StartTime = KeQueryPerformanceCounter(NULL);

    // Perform the write operation
    Status = WriteVirtual(
        ProcessHandle,
        (PVOID)(ULONG64)BaseAddress,
        Buffer,
        BufferSize,
        BytesWritten
    );

    // Record end time and calculate duration
    OperationResult->EndTime = KeQueryPerformanceCounter(NULL);
    KeQueryPerformanceCounter(&PerfFreq);
    OperationResult->DurationMicroseconds = (ULONG)(
        (OperationResult->EndTime.QuadPart - OperationResult->StartTime.QuadPart) * 1000000UL /
        (PerfFreq.QuadPart == 0 ? 1 : PerfFreq.QuadPart)
    );

    if (IS_SUCCESS(Status)) {
        OperationResult->Status = STATUS_SUCCESS;
        OperationResult->CompletedSize = *BytesWritten;
    }
    else {
        OperationResult->Status = Status;
        OperationResult->CompletedSize = 0;
        if (BytesWritten) {
            *BytesWritten = 0;
        }
    }

    return Status;
}

NTSTATUS
MemoryOperationWriteWithMapping(
    IN OUT PMANUAL_MAPPING_ENTRY MappingEntry,
    IN ULONGLONG RelativeAddress,
    IN PCVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesWritten
)
/*++
Routine Description:
    Writes memory to a manually mapped module at the specified relative address.

Arguments:
    MappingEntry - Manual mapping entry containing module information.
    RelativeAddress - Relative address within the mapped module.
    Buffer - Buffer containing the data to write.
    BufferSize - Size of the buffer.
    BytesWritten - Returns the number of bytes actually written.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    PVOID DestinationAddress;
    ULONG AvailableSize;

    // Validate the mapping entry
    if (MappingEntry == NULL ||
        MappingEntry->MappingBase == NULL ||
        MappingEntry->MappingSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calculate the destination address within the mapping
    DestinationAddress = (PCHAR)MappingEntry->MappingBase + RelativeAddress;

    // Verify the address is within the mapping bounds
    if (RelativeAddress >= MappingEntry->MappingSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Calculate available size from the relative address
    AvailableSize = (ULONG)(MappingEntry->MappingSize - RelativeAddress);
    if (BufferSize > AvailableSize) {
        BufferSize = AvailableSize;
    }

    // Check if the target section is writable
    if (MappingEntry->FirstSection && MappingEntry->SectionCount > 0) {
        PIMAGE_SECTION_HEADER CurrentSection;
        ULONG i;
        BOOLEAN SectionWritable = FALSE;

        CurrentSection = MappingEntry->FirstSection;

        for (i = 0; i < MappingEntry->SectionCount; i++) {
            ULONGLONG SectionStart = CurrentSection->VirtualAddress;
            ULONGLONG SectionEnd = SectionStart + CurrentSection->Misc.VirtualSize;

            if (RelativeAddress >= SectionStart &&
                RelativeAddress < SectionEnd) {
                // Check if section is writable
                if (CurrentSection->Characteristics & IMAGE_SCN_MEM_WRITE) {
                    SectionWritable = TRUE;
                }

                // Check if section has initialized data
                if (CurrentSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
                    // Write to initialized data section
                    PCHAR SectionData = (PCHAR)MappingEntry->MappingBase +
                        CurrentSection->VirtualAddress;
                    ULONG SectionOffset = (ULONG)(RelativeAddress - SectionStart);

                    RtlMoveMemory(
                        SectionData + SectionOffset,
                        Buffer,
                        BufferSize
                    );

                    if (BytesWritten) {
                        *BytesWritten = BufferSize;
                    }

                    Status = STATUS_SUCCESS;
                    SectionWritable = TRUE;
                    break;
                }
            }

            CurrentSection++;
        }

        if (!SectionWritable) {
            return STATUS_ACCESS_DENIED;
        }
    }
    else {
        // Fallback to direct memory copy
        RtlMoveMemory(DestinationAddress, Buffer, BufferSize);

        if (BytesWritten) {
            *BytesWritten = BufferSize;
        }

        Status = STATUS_SUCCESS;
    }

    // Update the mapping entry's last access time
    KeQuerySystemTimePrecise(&MappingEntry->LastAccessTime);

    return Status;
}

//------------------------------------------------------------------------------
// Memory Query Operations
//------------------------------------------------------------------------------

NTSTATUS
MemoryOperationQuery(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    OUT PMEMORY_REGION_DESCRIPTOR RegionDescriptor,
    OUT PULONG RegionSize
)
/*++
Routine Description:
    Queries memory information for a specified address in a target process.

Arguments:
    ProcessHandle - Handle to the target process.
    BaseAddress - Base address to query.
    RegionDescriptor - Descriptor to receive the region information.
    RegionSize - Returns the size of the queried region.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    SIZE_T BytesMapped = 0;
    MEMORY_BASIC_INFORMATION BasicInfo;

    // Validate input parameters
    if (ProcessHandle == NULL || RegionDescriptor == NULL || RegionSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize the region descriptor
    RtlZeroMemory(RegionDescriptor, sizeof(MEMORY_REGION_DESCRIPTOR));

    // Query the virtual memory
    Status = ZwQueryVirtualMemory(
        ProcessHandle,
        (PVOID)(ULONG64)BaseAddress,
        MemoryBasicInformation,
        &BasicInfo,
        sizeof(BasicInfo),
        &BytesMapped
    );

    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    // Populate the region descriptor with queried information
    RegionDescriptor->BaseAddress = (ULONG64)BasicInfo.BaseAddress;
    RegionDescriptor->RegionSize = (ULONG64)BasicInfo.RegionSize;
    RegionDescriptor->AllocationBase = (ULONGLONG)BasicInfo.AllocationBase;
    RegionDescriptor->AllocationProtect = BasicInfo.AllocationProtect;
    RegionDescriptor->State = BasicInfo.State;
    RegionDescriptor->Protect = BasicInfo.Protect;
    RegionDescriptor->Type = BasicInfo.Type;

    *RegionSize = (ULONG)BasicInfo.RegionSize;

    // Calculate and populate subsection information
    Status = MapVirtualMemoryRegion(
        ProcessHandle,
        BaseAddress,
        (ULONG)BasicInfo.RegionSize,
        RegionDescriptor
    );

    if (IS_SUCCESS(Status)) {
        RegionDescriptor->Flags |= REGION_FLAG_QUERIED;
    }

    return Status;
}

NTSTATUS
MemoryOperationQueryProtection(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    OUT PULONG ProtectionFlags
)
/*++
Routine Description:
    Queries the protection flags for a specified memory address.

Arguments:
    ProcessHandle - Handle to the target process.
    BaseAddress - Base address to query.
    ProtectionFlags - Returns the protection flags.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    MEMORY_BASIC_INFORMATION BasicInfo;
    SIZE_T BytesReturned;

    // Validate input parameters
    if (ProcessHandle == NULL || ProtectionFlags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Query the memory protection
    Status = ZwQueryVirtualMemory(
        ProcessHandle,
        (PVOID)(ULONG64)BaseAddress,
        MemoryBasicInformation,
        &BasicInfo,
        sizeof(BasicInfo),
        &BytesReturned
    );

    if (!NT_SUCCESS(Status) || BytesReturned == 0) {
        return STATUS_INVALID_ADDRESS;
    }

    // Extract the protection flags
    *ProtectionFlags = BasicInfo.Protect;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// Memory Protection Operations
//------------------------------------------------------------------------------

NTSTATUS
MemoryOperationProtect(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    IN ULONG NewProtect,
    IN ULONG RegionSize,
    OUT PULONG OldProtect
)
/*++
Routine Description:
    Changes the memory protection for a specified region in a target process.

Arguments:
    ProcessHandle - Handle to the target process.
    BaseAddress - Base address of the region to protect.
    NewProtect - New protection flags.
    RegionSize - Size of the region to protect.
    OldProtect - Returns the previous protection flags.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    SIZE_T BytesProtected;

    // Validate input parameters
    if (ProcessHandle == NULL || OldProtect == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate the new protection value
    if (NewProtect == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Change the memory protection
    {
        PVOID ProtectBase = (PVOID)(ULONG_PTR)BaseAddress;
        SIZE_T ProtectSize = RegionSize;
        Status = ZwProtectVirtualMemory(
            ProcessHandle,
            &ProtectBase,
            &ProtectSize,
            NewProtect,
            OldProtect
        );
    }

    if (IS_SUCCESS(Status)) {
        // Flush instruction cache to ensure the new protection is visible
        ZwFlushInstructionCache(
            ProcessHandle,
            (PVOID)(ULONG64)BaseAddress,
            RegionSize
        );
    }

    return Status;
}

NTSTATUS
MemoryOperationProtectWithMapping(
    IN PMANUAL_MAPPING_ENTRY MappingEntry,
    IN ULONGLONG RelativeAddress,
    IN ULONG RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
)
/*++
Routine Description:
    Changes the memory protection for a region within a manually mapped module.

Arguments:
    MappingEntry - Manual mapping entry containing module information.
    RelativeAddress - Relative address of the region to protect.
    RegionSize - Size of the region to protect.
    NewProtect - New protection flags.
    OldProtect - Returns the previous protection flags.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    PIMAGE_SECTION_HEADER TargetSection;
    ULONG i;

    // Validate input parameters
    if (MappingEntry == NULL || MappingEntry->MappingBase == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Find the target section
    TargetSection = NULL;

    if (MappingEntry->FirstSection && MappingEntry->SectionCount > 0) {
        for (i = 0; i < MappingEntry->SectionCount; i++) {
            ULONGLONG SectionStart = MappingEntry->FirstSection[i].VirtualAddress;
            ULONGLONG SectionEnd = SectionStart + MappingEntry->FirstSection[i].Misc.VirtualSize;

            if (RelativeAddress >= SectionStart &&
                RelativeAddress < SectionEnd) {
                TargetSection = &MappingEntry->FirstSection[i];
                break;
            }
        }
    }

    if (TargetSection == NULL) {
        return STATUS_SECTION_NOT_FOUND;
    }

    // Store the old protection
    *OldProtect = (ULONG)TargetSection->Characteristics &
        (IMAGE_SCN_MEM_NOT_PURGED | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
         IMAGE_SCN_MEM_WRITE);

    // Update the section characteristics with the new protection
    TargetSection->Characteristics &=
        ~(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    TargetSection->Characteristics |= NewProtect;

    // Mark the mapping entry as having been modified
    MappingEntry->MappingFlags |= MAPPING_FLAG_INITIALIZED;
    KeQuerySystemTimePrecise(&MappingEntry->LastAccessTime);

    Status = STATUS_SUCCESS;

    return Status;
}

//------------------------------------------------------------------------------
// Memory Commit/Decommit Operations
//------------------------------------------------------------------------------

NTSTATUS
MemoryOperationCommit(
    IN PMANUAL_MAPPING_ENTRY MappingEntry,
    IN ULONGLONG RelativeAddress,
    IN ULONG CommitSize,
    IN ULONG Protect,
    OUT PBOOLEAN CommitSuccessful
)
/*++
Routine Description:
    Commits memory within a manually mapped module.

Arguments:
    MappingEntry - Manual mapping entry containing module information.
    RelativeAddress - Relative address to commit.
    CommitSize - Size of memory to commit.
    Protect - Protection flags for the committed memory.
    CommitSuccessful - Returns whether the commit was successful.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;
    PVOID CommitBase;

    // Validate input parameters
    if (MappingEntry == NULL || CommitSuccessful == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize output
    *CommitSuccessful = FALSE;

    // Calculate the commit base address
    CommitBase = (PCHAR)MappingEntry->MappingBase + RelativeAddress;

    // Verify the commit is within bounds
    if (RelativeAddress + CommitSize > MappingEntry->MappingSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Update the mapping entry's commit size
    MappingEntry->CommitSize += CommitSize;

    // Mark the memory as committed
    MappingEntry->MappingFlags |= MAPPING_FLAG_INITIALIZED;

    *CommitSuccessful = TRUE;
    Status = STATUS_SUCCESS;

    return Status;
}

NTSTATUS
MemoryOperationDecommit(
    IN PMANUAL_MAPPING_ENTRY MappingEntry,
    IN ULONGLONG RelativeAddress,
    IN ULONG DecommitSize,
    OUT PBOOLEAN DecommitSuccessful
)
/*++
Routine Description:
    Decommit memory within a manually mapped module.

Arguments:
    MappingEntry - Manual mapping entry containing module information.
    RelativeAddress - Relative address to decommit.
    DecommitSize - Size of memory to decommit.
    DecommitSuccessful - Returns whether the decommit was successful.

Return Value:
    STATUS_SUCCESS on success, appropriate NTSTATUS on failure.
--*/
{
    NTSTATUS Status;

    // Validate input parameters
    if (MappingEntry == NULL || DecommitSuccessful == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize output
    *DecommitSuccessful = FALSE;

    // Verify the decommit is within bounds
    if (MappingEntry->CommitSize < DecommitSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // Update the mapping entry's commit size
    MappingEntry->CommitSize -= DecommitSize;

    // Mark the memory as decommitted
    *DecommitSuccessful = TRUE;
    Status = STATUS_SUCCESS;

    return Status;
}

//------------------------------------------------------------------------------
// Internal Helper Functions
//------------------------------------------------------------------------------

static NTSTATUS
InitializeMemoryOperationResult(
    OUT PMEMORY_OPERATION_RESULT Result,
    IN MEMORY_OPERATION OperationType,
    IN ULONGLONG TargetAddress,
    IN ULONG RequestedSize
)
{
    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(MEMORY_OPERATION_RESULT));

    Result->OperationType = OperationType;
    Result->TargetAddress = TargetAddress;
    Result->RequestedSize = RequestedSize;
    Result->Status = STATUS_SUCCESS;

    return STATUS_SUCCESS;
}

static NTSTATUS
ValidateMemoryAddress(
    IN HANDLE ProcessHandle,
    IN ULONGLONG Address,
    IN ULONG Size,
    OUT PBOOLEAN IsValid
)
{
    NTSTATUS Status;
    MEMORY_BASIC_INFORMATION BasicInfo;
    SIZE_T BytesReturned;

    if (IsValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    UNREFERENCED_PARAMETER(Size);

    *IsValid = FALSE;

    // Query the memory address
    Status = ZwQueryVirtualMemory(
        ProcessHandle,
        (PVOID)(ULONG64)Address,
        MemoryBasicInformation,
        &BasicInfo,
        sizeof(BasicInfo),
        &BytesReturned
    );

    if (NT_SUCCESS(Status) && BytesReturned == sizeof(BasicInfo)) {
        // Verify the address range is valid
        if (BasicInfo.State & MEM_COMMIT) {
            *IsValid = TRUE;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_INVALID_ADDRESS;
}

static NTSTATUS
ReadVirtual(
    IN HANDLE ProcessHandle,
    IN PVOID Address,
    OUT PVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesRead
)
{
    NTSTATUS Status;
    SIZE_T ReadSize = 0;
    PEPROCESS TargetProcess = NULL;

    Status = ResolveProcessObject(
        ProcessHandle,
        PROCESS_VM_READ,
        &TargetProcess
    );
    if (!NT_SUCCESS(Status)) {
        if (BytesRead != NULL) {
            *BytesRead = 0;
        }
        return Status;
    }

    Status = MmCopyVirtualMemory(
        TargetProcess,
        Address,
        PsGetCurrentProcess(),
        Buffer,
        BufferSize,
        KernelMode,
        &ReadSize
    );
    ObDereferenceObject(TargetProcess);

    if (BytesRead != NULL) {
        *BytesRead = (ULONG)ReadSize;
    }

    return Status;
}

static NTSTATUS
WriteVirtual(
    IN HANDLE ProcessHandle,
    IN PVOID Address,
    IN PCVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG BytesWritten
)
{
    NTSTATUS Status;
    SIZE_T WrittenSize = 0;
    PEPROCESS TargetProcess = NULL;

    Status = ResolveProcessObject(
        ProcessHandle,
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        &TargetProcess
    );
    if (!NT_SUCCESS(Status)) {
        if (BytesWritten != NULL) {
            *BytesWritten = 0;
        }
        return Status;
    }

    Status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)Buffer,
        TargetProcess,
        Address,
        BufferSize,
        KernelMode,
        &WrittenSize
    );
    ObDereferenceObject(TargetProcess);

    if (BytesWritten != NULL) {
        *BytesWritten = (ULONG)WrittenSize;
    }

    return Status;
}

static NTSTATUS
ResolveProcessObject(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PEPROCESS* ProcessObject
)
{
    if (ProcessObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ProcessObject = NULL;
    return ObReferenceObjectByHandle(
        ProcessHandle,
        DesiredAccess,
        *PsProcessType,
        KernelMode,
        (PVOID*)ProcessObject,
        NULL
    );
}

static NTSTATUS
CalculateMemoryChecksum(
    IN PVOID Buffer,
    IN ULONG BufferSize,
    IN ULONG Algorithm,
    OUT PULONG Checksum
)
{
    if (Buffer == NULL || Checksum == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calculate checksum based on the specified algorithm
    switch (Algorithm) {
        case CHECKSUM_ALGORITHM_CRC32:
            *Checksum = (ULONG)RtlComputeCrc32(0, Buffer, BufferSize);
            break;

        case CHECKSUM_ALGORITHM_CRC64:
            *Checksum = (ULONG)(RtlComputeCrc32(0, Buffer, BufferSize) ^
                               (RtlComputeCrc32(0, Buffer, BufferSize) << 32));
            break;

        case CHECKSUM_ALGORITHM_SHA256:
            // For SHA256, we use a simplified hash computation
            *Checksum = (ULONG)RtlComputeCrc32(0, Buffer, BufferSize);
            break;

        default:
            *Checksum = (ULONG)RtlComputeCrc32(0, Buffer, BufferSize);
            break;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
MapVirtualMemoryRegion(
    IN HANDLE ProcessHandle,
    IN ULONGLONG BaseAddress,
    IN ULONG RegionSize,
    OUT PMEMORY_REGION_DESCRIPTOR RegionDescriptor
)
{
    NTSTATUS Status;
    ULONG SubsectionCount = 0;
    ULONGLONG CurrentAddress = BaseAddress;

    if (RegionDescriptor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Enumerate subsections within the region
    while (CurrentAddress < (BaseAddress + RegionSize)) {
        MEMORY_BASIC_INFORMATION BasicInfo;
        SIZE_T BytesReturned;

        Status = ZwQueryVirtualMemory(
            ProcessHandle,
            (PVOID)(ULONG_PTR)CurrentAddress,
            MemoryBasicInformation,
            &BasicInfo,
            sizeof(BasicInfo),
            &BytesReturned
        );

        if (!NT_SUCCESS(Status) || BytesReturned == 0) {
            break;
        }

        SubsectionCount++;
        CurrentAddress += (ULONGLONG)BasicInfo.RegionSize;
    }

    RegionDescriptor->SubsectionCount = SubsectionCount;

    // Allocate subsection array if needed
    if (SubsectionCount > 0) {
        RegionDescriptor->SubsectionArray = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            SubsectionCount * sizeof(MEMORY_BASIC_INFORMATION),
            MEMORY_OPERATION_TAG
        );

        if (RegionDescriptor->SubsectionArray == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RegionDescriptor->PrivateDataSize = SubsectionCount * sizeof(MEMORY_BASIC_INFORMATION);
    }

    Status = STATUS_SUCCESS;

    return Status;
}
