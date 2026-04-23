/*
 * Stealth Kernel Driver - Driver Entry Points
 *
 * Main driver initialization, cleanup, and I/O request dispatch.
 * Implements custom DriverMapEntry for manual mapping support.
 *
 * Target: Windows 10/11 x64
 * Environment: No-CRT
 */

#include "StealthDriver.h"

static PDRIVER_GLOBAL_STATE GetGlobalStateFromDevice(
    IN PDEVICE_OBJECT DeviceObject
)
{
    PDRIVER_DEVICE_EXTENSION Extension;

    if (DeviceObject == NULL || DeviceObject->DeviceExtension == NULL) {
        return &G_DriverState;
    }

    Extension = (PDRIVER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (Extension->Signature != DEVICE_EXTENSION_TAG || Extension->GlobalState == NULL) {
        return &G_DriverState;
    }

    return Extension->GlobalState;
}

NTSTATUS DispatchIORequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
);

NTSTATUS HandleCreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN BOOLEAN IsCreate
);

NTSTATUS HandleDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
);

NTSTATUS HandleInternalDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
);

NTSTATUS HandleReadWrite(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN BOOLEAN IsRead
);

NTSTATUS HandleReadMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
);

NTSTATUS HandleWriteMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
);

NTSTATUS HandleQueryMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG BytesReturned
);

NTSTATUS HandleProtectMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
);

NTSTATUS HandleEraseMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
);

NTSTATUS HandleQueryDriverState(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG BytesReturned
);

//------------------------------------------------------------------------------
// Driver Entry Points - Function Pointers
//------------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(INIT, DriverMapEntry)
    #pragma alloc_text(PAGE, DriverCleanup)
#endif

//------------------------------------------------------------------------------
// DriverEntry
//
// Main entry point for the stealth kernel driver.
// Initializes driver state, creates device objects, and establishes
// the I/O request dispatch mechanisms.
//
// Parameters:
//   DriverObject     - Handle to driver object
//   RegistryPath     - Unicode string containing the registry path
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    PDEVICE_OBJECT DeviceObject;

    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialize driver global state
    Status = InitializeDriverGlobalState(&G_DriverState);
    if (!IS_SUCCESS(Status)) {
        return Status;
    }

    // Set up cleanup routine
    if (DriverObject->DriverExtension != NULL) {
        DriverObject->DriverExtension->AddDevice = DriverAddDevice;
    }
    DriverObject->DriverUnload = DriverCleanup;

    // Create device name
    RtlInitUnicodeString(&DeviceName, STEALTH_DEVICE_NAME);

    // Create device object
    Status = IoCreateDevice(
        DriverObject,
        sizeof(DRIVER_DEVICE_EXTENSION),
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
    );

    if (!IS_SUCCESS(Status)) {
        CleanupDriverGlobalState(&G_DriverState);
        return Status;
    }

    // Initialize device extension
    {
        PDRIVER_DEVICE_EXTENSION DeviceExtension =
            (PDRIVER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
        if (DeviceExtension != NULL) {
            RtlZeroMemory(DeviceExtension, sizeof(DRIVER_DEVICE_EXTENSION));
            DeviceExtension->GlobalState = &G_DriverState;
            DeviceExtension->Signature = DEVICE_EXTENSION_TAG;
        }
    }

    // Configure device characteristics
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DeviceObject->Flags |= DO_BUFFERED_IO;

    // Set default access state
    G_DriverState.AccessState = DEVICE_ACCESS_GRANTED;

    // Initialize shared signaling
    Status = InitializeSharedSignaling(&G_DriverState);
    if (!IS_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        CleanupDriverGlobalState(&G_DriverState);
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchIORequest;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchIORequest;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIORequest;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = DispatchIORequest;
    DriverObject->MajorFunction[IRP_MJ_READ] = DispatchIORequest;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchIORequest;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// DriverAddDevice
//
// Called by the system to add a new device instance.
//
// Parameters:
//   DriverObject     - Handle to driver object
//   DeviceObject     - Handle to device object
//
// Returns:
//   STATUS_SUCCESS on success, NTSTATUS error code otherwise
//------------------------------------------------------------------------------

NTSTATUS DriverAddDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT PhysicalDeviceObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(PhysicalDeviceObject);

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// DriverCleanup
//
// Cleanup routine called when the driver is unloaded.
// Releases all allocated resources and updates driver state.
//
// Parameters:
//   DriverObject     - Handle to driver object
//------------------------------------------------------------------------------

VOID DriverCleanup(
    IN PDRIVER_OBJECT DriverObject
)
{
    PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

    if (DeviceObject != NULL) {
        // Delete device object
        IoDeleteDevice(DeviceObject);
    }

    // Clean up driver global state
    CleanupDriverGlobalState(&G_DriverState);
}

//------------------------------------------------------------------------------
// DispatchIORequest
//
// Main I/O request dispatch function.
// Routes requests to appropriate handlers based on MajorFunction.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//
// Returns:
//   NTSTATUS - Status of the I/O operation
//------------------------------------------------------------------------------

NTSTATUS DispatchIORequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION CurrentIrp;
    ULONG MajorFunction;
    PDRIVER_GLOBAL_STATE GlobalState;

    // Get current stack location
    CurrentIrp = IoGetCurrentIrpStackLocation(Irp);
    MajorFunction = CurrentIrp->MajorFunction;

    // Get device extension (driver global state)
    GlobalState = GetGlobalStateFromDevice(DeviceObject);

    // Route based on major function
    switch (MajorFunction) {
    case IRP_MJ_CREATE:
        Status = HandleCreateClose(DeviceObject, Irp, TRUE);
        break;

    case IRP_MJ_CLOSE:
        Status = HandleCreateClose(DeviceObject, Irp, FALSE);
        break;

    case IRP_MJ_DEVICE_CONTROL:
        Status = HandleDeviceControl(DeviceObject, Irp);
        break;

    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        Status = HandleInternalDeviceControl(DeviceObject, Irp);
        break;

    case IRP_MJ_READ:
        Status = HandleReadWrite(DeviceObject, Irp, TRUE);
        break;

    case IRP_MJ_WRITE:
        Status = HandleReadWrite(DeviceObject, Irp, FALSE);
        break;

    default:
        Status = STATUS_NOT_SUPPORTED;
        break;
    }

    // Update statistics
    if (GlobalState != NULL) {
        GlobalState->TotalCommandProcessed++;

        if (!IS_SUCCESS(Status)) {
            GlobalState->TotalErrors++;
        }
    }

    return Status;
}

//------------------------------------------------------------------------------
// HandleCreateClose
//
// Handles IRP_MJ_CREATE and IRP_MJ_CLOSE requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   IsCreate         - TRUE for CREATE, FALSE for CLOSE
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleCreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN BOOLEAN IsCreate
)
{
    NTSTATUS Status;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (IsCreate) {
        // Set access state
        G_DriverState.AccessState = DEVICE_ACCESS_GRANTED;

        Status = STATUS_SUCCESS;
        G_DriverState.TotalCommandProcessed++;
    }
    else {
        // Clear access state
        G_DriverState.AccessState = DEVICE_ACCESS_REVOKED;

        Status = STATUS_SUCCESS;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

//------------------------------------------------------------------------------
// HandleDeviceControl
//
// Handles IRP_MJ_DEVICE_CONTROL requests.
// Processes IOCTL commands for memory operations.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION CurrentIrp;
    ULONG ControlCode;
    PVOID InputBuffer;
    ULONG InputBufferLength;
    PVOID OutputBuffer;
    ULONG OutputBufferLength;
    PULONG BytesReturned;

    CurrentIrp = IoGetCurrentIrpStackLocation(Irp);
    ControlCode = CurrentIrp->Parameters.DeviceIoControl.IoControlCode;
    InputBuffer = Irp->AssociatedIrp.SystemBuffer;
    InputBufferLength = CurrentIrp->Parameters.DeviceIoControl.InputBufferLength;
    OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
    OutputBufferLength = CurrentIrp->Parameters.DeviceIoControl.OutputBufferLength;
    BytesReturned = &Irp->IoStatus.Information;

    *BytesReturned = 0;

    // Route IOCTL commands
    switch (ControlCode) {
    case IOCTL_READ_MEMORY:
        Status = HandleReadMemory(DeviceObject, Irp, InputBuffer, InputBufferLength, BytesReturned);
        break;

    case IOCTL_WRITE_MEMORY:
        Status = HandleWriteMemory(DeviceObject, Irp, InputBuffer, InputBufferLength, BytesReturned);
        break;

    case IOCTL_QUERY_MEMORY:
        Status = HandleQueryMemory(DeviceObject, Irp, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, BytesReturned);
        break;

    case IOCTL_PROTECT_MEMORY:
        Status = HandleProtectMemory(DeviceObject, Irp, InputBuffer, InputBufferLength, BytesReturned);
        break;

    case IOCTL_ERASE_MEMORY:
        Status = HandleEraseMemory(DeviceObject, Irp, InputBuffer, InputBufferLength, BytesReturned);
        break;

    case IOCTL_QUERY_DRIVER_STATE:
        Status = HandleQueryDriverState(DeviceObject, Irp, OutputBuffer, OutputBufferLength, BytesReturned);
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

//------------------------------------------------------------------------------
// HandleReadMemory
//
// Handles memory read IOCTL requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   InputBuffer      - Pointer to input buffer
//   InputBufferLength - Size of input buffer
//   BytesReturned    - Output bytes returned
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleReadMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
)
{
    NTSTATUS Status;
    PREAD_MEMORY_INPUT Input;
    ULONG BytesRead;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (InputBufferLength < sizeof(READ_MEMORY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PREAD_MEMORY_INPUT)InputBuffer;
    if (Input->DestinationBuffer == NULL || Input->BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((ULONG_PTR)Input->DestinationBuffer > (ULONG_PTR)MmHighestUserAddress) {
        return STATUS_ACCESS_VIOLATION;
    }
    *BytesReturned = 0;

    // Perform secure read operation
    Status = SecureReadMemory(
        Input->ProcessId,
        Input->SourceAddress,
        Input->DestinationBuffer,
        Input->BufferSize,
        &BytesRead
    );

    if (IS_SUCCESS(Status)) {
        *BytesReturned = BytesRead;
    }

    return Status;
}

//------------------------------------------------------------------------------
// HandleWriteMemory
//
// Handles memory write IOCTL requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   InputBuffer      - Pointer to input buffer
//   InputBufferLength - Size of input buffer
//   BytesReturned    - Output bytes returned
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleWriteMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
)
{
    NTSTATUS Status;
    PWRITE_MEMORY_INPUT Input;
    ULONG BytesWritten;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (InputBufferLength < sizeof(WRITE_MEMORY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PWRITE_MEMORY_INPUT)InputBuffer;
    if (Input->SourceBuffer == NULL || Input->BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((ULONG_PTR)Input->SourceBuffer > (ULONG_PTR)MmHighestUserAddress) {
        return STATUS_ACCESS_VIOLATION;
    }
    *BytesReturned = 0;

    // Perform secure write operation
    Status = SecureWriteMemory(
        Input->ProcessId,
        Input->DestinationAddress,
        Input->SourceBuffer,
        Input->BufferSize,
        &BytesWritten
    );

    if (IS_SUCCESS(Status)) {
        *BytesReturned = BytesWritten;
    }

    return Status;
}

//------------------------------------------------------------------------------
// HandleQueryMemory
//
// Handles memory query IOCTL requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   InputBuffer      - Pointer to input buffer
//   InputBufferLength - Size of input buffer
//   OutputBuffer     - Pointer to output buffer
//   OutputBufferLength - Size of output buffer
//   BytesReturned    - Output bytes returned
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleQueryMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG BytesReturned
)
{
    NTSTATUS Status;
    PQUERY_MEMORY_INPUT Input;
    PMEMORY_REGION_DESCRIPTOR RegionDescriptor;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (InputBufferLength < sizeof(QUERY_MEMORY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferLength < sizeof(MEMORY_REGION_DESCRIPTOR)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PQUERY_MEMORY_INPUT)InputBuffer;
    RegionDescriptor = (PMEMORY_REGION_DESCRIPTOR)OutputBuffer;
    *BytesReturned = 0;

    // Query memory information
    Status = QueryMemoryInformation(
        Input->ProcessId,
        Input->Address,
        RegionDescriptor
    );

    if (IS_SUCCESS(Status)) {
        *BytesReturned = sizeof(MEMORY_REGION_DESCRIPTOR);
    }

    return Status;
}

//------------------------------------------------------------------------------
// HandleProtectMemory
//
// Handles memory protection IOCTL requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   InputBuffer      - Pointer to input buffer
//   InputBufferLength - Size of input buffer
//   BytesReturned    - Output bytes returned
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleProtectMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
)
{
    NTSTATUS Status;
    PPROTECT_MEMORY_INPUT Input;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (InputBufferLength < sizeof(PROTECT_MEMORY_INPUT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PPROTECT_MEMORY_INPUT)InputBuffer;
    *BytesReturned = 0;

    // Protect memory region
    Status = ProtectMemoryRegion(
        Input->ProcessId,
        Input->BaseAddress,
        Input->RegionSize,
        Input->NewProtection
    );

    if (IS_SUCCESS(Status)) {
        *BytesReturned = 0;
    }

    return Status;
}

//------------------------------------------------------------------------------
// HandleEraseMemory
//
// Handles memory erase IOCTL requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   InputBuffer      - Pointer to input buffer
//   InputBufferLength - Size of input buffer
//   BytesReturned    - Output bytes returned
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleEraseMemory(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PULONG BytesReturned
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);

    *BytesReturned = 0;

    // Erase operation would be implemented here
    G_DriverState.TotalErasureOperations++;

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// HandleQueryDriverState
//
// Handles driver state query IOCTL requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   OutputBuffer     - Pointer to output buffer
//   OutputBufferLength - Size of output buffer
//   BytesReturned    - Output bytes returned
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleQueryDriverState(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG BytesReturned
)
{
    NTSTATUS Status;
    PDRIVER_STATE_QUERY Output;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (OutputBufferLength < sizeof(DRIVER_STATE_QUERY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Output = (PDRIVER_STATE_QUERY)OutputBuffer;
    *BytesReturned = 0;

    // Populate driver state query
    Output->DriverVersion = G_DriverState.DriverVersion;
    Output->TotalReadOperations = G_DriverState.TotalReadOperations;
    Output->TotalWriteOperations = G_DriverState.TotalWriteOperations;
    Output->TotalErasureOperations = G_DriverState.TotalErasureOperations;
    Output->TotalCommandProcessed = G_DriverState.TotalCommandProcessed;
    Output->TotalErrors = G_DriverState.TotalErrors;
    Output->TotalTimeouts = G_DriverState.TotalTimeouts;
    Output->LoadTime = G_DriverState.LoadTime;

    *BytesReturned = sizeof(DRIVER_STATE_QUERY);
    Status = STATUS_SUCCESS;

    return Status;
}

//------------------------------------------------------------------------------
// HandleInternalDeviceControl
//
// Handles internal device control requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleInternalDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//------------------------------------------------------------------------------
// HandleReadWrite
//
// Handles IRP_MJ_READ and IRP_MJ_WRITE requests.
//
// Parameters:
//   DeviceObject     - Handle to device object
//   Irp              - Pointer to I/O request packet
//   IsRead           - TRUE for READ, FALSE for WRITE
//
// Returns:
//   NTSTATUS - Status of the operation
//------------------------------------------------------------------------------

NTSTATUS HandleReadWrite(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN BOOLEAN IsRead
)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    // Basic read/write handling
    Status = STATUS_SUCCESS;

    if (IsRead) {
        G_DriverState.TotalReadOperations++;
    }
    else {
        G_DriverState.TotalWriteOperations++;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
