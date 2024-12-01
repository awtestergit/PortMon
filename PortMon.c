#include <ntddk.h>
#define NDIS688
#pragma warning(disable:4201)  // Disable warning about nameless struct/union
#include <ndis.h> // Network Driver Interface definitions (defines NET_BUFFER_LIST)
#pragma warning(default:4201)  // Re-enable the warning after the include 
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>
#include <initguid.h>


# pragma region GUIDs
// Define {d700f2c9-cc76-4d99-9364-475dbfd8b35b}
DEFINE_GUID(GUID_PORTMON_CALLOUT, 0xd700f2c9, 0xcc76, 0x4d99, 0x93, 0x64, 0x47, 0x5d, 0xbf, 0xd8, 0xb3, 0x5b);
// b16b0a6e-2b2a-41a3-8b39-bd3ffc855ff8
DEFINE_GUID(
    GUID_PORTMON_CALLOUT_CLOSURE,
    0xb16b0a6e,
    0x2b2a,
    0x41a3,
    0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8
);

#if !defined(FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4)
DEFINE_GUID(
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
    0x1247d66d,
    0x0b60,
    0x4a15,
    0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c
);
#endif

// b4766427-e2a2-467a-bd7e-dbcd1bd85a09
#if !defined(FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4)
DEFINE_GUID(
    FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
    0xb4766427,
    0xe2a2,
    0x467a,
    0xbd, 0x7e, 0xdb, 0xcd, 0x1b, 0xd8, 0x5a, 0x09
);
#endif

// 0104fd7e-c825-414e-94c9-f0d525bbc169
DEFINE_GUID(
    PORTMON_SUBLAYER,
    0x0104fd7e,
    0xc825,
    0x414e,
    0x94, 0xc9, 0xf0, 0xd5, 0x25, 0xbb, 0xc1, 0x69
);

#pragma endregion


#pragma region Ioctl

#define IOCTL_GET_PORT_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define DEVICE_NAME L"\\Device\\PortMonDriver"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\PortMonDriver"

#pragma endregion

#pragma region WFP Helper Functions and Structures

#define CALLOUT_NAME L"WFP Port Monitoring Callout"
#define CALLOUT_DESC L"Monitors local port assignment and release events."

NTSTATUS RegisterWfpCallout(PDEVICE_OBJECT DeviceObject);
void UnregisterWfpCallout();
void NTAPI CalloutClassifyFn(
    const FWPS_INCOMING_VALUES* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT* ClassifyOut
);
NTSTATUS NTAPI
NotifyFn(
    IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID* filterKey,
    IN const FWPS_FILTER3* filter
);

#pragma endregion

#pragma region structure and globals

#define MAX_EVENTS 1024

typedef struct _PORT_EVENT {
    UINT16 Protocol;        // Protocol: TCP/UDP
    UINT16 PortNumber;      // Port number
    UINT32 ProcessId;       // Process ID
    LARGE_INTEGER Timestamp; // Event timestamp
    BOOLEAN IsAssignment;   // Assignment (TRUE) or release (FALSE)
} PORT_EVENT, * PPORT_EVENT;

typedef struct _EVENT_QUEUE {
    PORT_EVENT Events[MAX_EVENTS];
    volatile ULONG Head;
    volatile ULONG Tail;
    KEVENT EventClose; //  close event
    KEVENT EventAvailable; // Signaling event
    FAST_MUTEX Mutex;      // Protect shared resources
} EVENT_QUEUE, * PEVENT_QUEUE;

static EVENT_QUEUE gEventQueue;
static PDEVICE_OBJECT gDeviceObject = NULL;
static UNICODE_STRING gSymbolicLinkName;
static HANDLE gEngineHandle = NULL;
static UINT32 gCalloutId = 0;
static UINT32 gClosureCalloutId = 0;

#pragma endregion

#pragma region Event Queue Implementation

void InitializeEventQueue() {
    gEventQueue.Head = 0;
    gEventQueue.Tail = 0;
    KeInitializeEvent(&gEventQueue.EventAvailable, NotificationEvent, FALSE); // signaling event
    KeInitializeEvent(&gEventQueue.EventClose, NotificationEvent, FALSE); // close event
    ExInitializeFastMutex(&gEventQueue.Mutex);
}

void PushEvent(PORT_EVENT Event) {
    ExAcquireFastMutex(&gEventQueue.Mutex);

    ULONG nextTail = (gEventQueue.Tail + 1) % MAX_EVENTS;

    if (nextTail != gEventQueue.Head) {
        gEventQueue.Events[gEventQueue.Tail] = Event;
        gEventQueue.Tail = nextTail;
        KeSetEvent(&gEventQueue.EventAvailable, 0, FALSE);
    }
    else {
        DbgPrint("Event queue overflow, dropping event\n");
    }

    ExReleaseFastMutex(&gEventQueue.Mutex);
}

#pragma endregion

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS IoCreateHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoCleanupHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void PushEvent(PORT_EVENT Event);
NTSTATUS MonitorPortEvents(); // Placeholder for WFP implementation
void StopMonitoringPortEvents();

#pragma region Driver Entry and Unload

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;
    UNICODE_STRING DeviceName;

    DbgPrint("Enter driver entry\n");

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&gSymbolicLinkName, SYMBOLIC_LINK_NAME);

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &gDeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to create device: %08x\n", Status);
        return Status;
    }

    Status = IoCreateSymbolicLink(&gSymbolicLinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to create symbolic link: %08x\n", Status);
        IoDeleteDevice(gDeviceObject);
        return Status;
    }

    InitializeEventQueue();

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreateHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = IoCleanupHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlHandler;
    DriverObject->DriverUnload = DriverUnload;

    // Start monitoring port events
    Status = MonitorPortEvents();
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to start WFP monitoring: %08x\n", Status);
        IoDeleteSymbolicLink(&gSymbolicLinkName);
        IoDeleteDevice(gDeviceObject);
        return Status;
    }

    DbgPrint("Driver initialized successfully\n");
    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DevObj) {
    UNREFERENCED_PARAMETER(DevObj);

    DbgPrint("Driver unloading...\n");

    StopMonitoringPortEvents();

    IoDeleteSymbolicLink(&gSymbolicLinkName);
    IoDeleteDevice(gDeviceObject);

    DbgPrint("Driver unloaded successfully\n");
}

#pragma endregion

#pragma region IRP Handlers

NTSTATUS IoCreateHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    DbgPrint("On create handler\n");
    KeResetEvent(&gEventQueue.EventClose); // reset stop signal
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IoCloseHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    DbgPrint("On close handler\n");
    KeSetEvent(&gEventQueue.EventClose, 0, FALSE); // send close signal, in case the handler still waiting
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IoCleanupHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    DbgPrint("Io cleanup handler\n");
    KeSetEvent(&gEventQueue.EventClose, 0, FALSE); // send close signal, in case the handler still waiting
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IoControlHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);

    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesTransferred = 0;
    PPORT_EVENT Buffer = NULL;
    PVOID objects[2];
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;  // 1 second timeout

    // DbgPrint("Receive device io code: 0X%x\n", IoStack->Parameters.DeviceIoControl.IoControlCode);
    // DbgPrint("Receive device waiting for code: 0X%x \n", IOCTL_GET_PORT_EVENTS);
    if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_PORT_EVENTS) {
        // DbgPrint("Received port event code\n");

        // Wait for an event to be available
        objects[0] = &gEventQueue.EventAvailable;
        objects[1] = &gEventQueue.EventClose;
        NTSTATUS WaitStatus = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, &Timeout, NULL);
        switch (WaitStatus) {
        case STATUS_TIMEOUT:
            // at timeout, cancel this ioctl, and user will do another round of pulling
            // DbgPrint("iocontrolhandler wait timeout\n");
            Status = STATUS_CANCELLED;
            break;

        case STATUS_WAIT_1:
            // close signal
            DbgPrint("Receive close signal, exit IoControlHandler\n");
            Status = STATUS_CANCELLED;
            // bytes returned is 0
            break;
        case STATUS_WAIT_0:
            // signaling event
            // Fetch events from the queue
            // DbgPrint("Receive port event ioctl, processing buffer now\n");
            Buffer = (PPORT_EVENT)Irp->AssociatedIrp.SystemBuffer;
            ULONG Count = 0;

            ExAcquireFastMutex(&gEventQueue.Mutex);

            // TODO: improvement of examinng the output buffer length, return ERROR_INSUFFICIENT_BUFFER if too small
            // DbgPrint("Outputbuffer length: %d\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
            // DbgPrint("Outputbuffer event size: %d\n", (int)sizeof(PORT_EVENT));
            // DbgPrint("Outputbuffer for event: %d\n", (int)(IoStack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(PORT_EVENT)));

            while (gEventQueue.Head != gEventQueue.Tail && Count < IoStack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(PORT_EVENT)) {
                Buffer[Count++] = gEventQueue.Events[gEventQueue.Head];
                gEventQueue.Head = (gEventQueue.Head + 1) % MAX_EVENTS;
            }

            if (gEventQueue.Head == gEventQueue.Tail) {
                // reset head and tail
                gEventQueue.Head = 0;
                gEventQueue.Tail = 0;
                KeResetEvent(&gEventQueue.EventAvailable); // reset signal
            }

            ExReleaseFastMutex(&gEventQueue.Mutex);
            BytesTransferred = Count * sizeof(PORT_EVENT);
            // DbgPrint("Receive port event ioctl, transferred bytes count: %d\n", BytesTransferred);
            break;
        default:
            // Handle other possible return values
            Status = STATUS_INVALID_DEVICE_REQUEST;
            DbgPrint("Wait failed with status 0x%X\n", WaitStatus);
            break;
        }
    }
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesTransferred;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

#pragma endregion

#pragma region WFP Monitoring Placeholder
NTSTATUS MonitorPortEvents() {
    NTSTATUS Status;

    FWPM_SESSION Session = { 0 };
    Session.displayData.name = L"Port Monitoring Session";
    Session.displayData.description = L"Session for monitoring port changes.";
    Session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    Status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &Session, &gEngineHandle);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to open WFP engine: %08x\n", Status);
        return Status;
    }

    Status = RegisterWfpCallout(gDeviceObject);
    if (!NT_SUCCESS(Status)) {
        FwpmEngineClose(gEngineHandle);
        gEngineHandle = NULL;
        DbgPrint("Failed to register WFP callout: %08x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

void StopMonitoringPortEvents() {
    DbgPrint("Stop monitor...\n");

    // close signal
    KeSetEvent(&gEventQueue.EventClose, 0, FALSE);
    UnregisterWfpCallout();

    if (gEngineHandle) {
        FwpmEngineClose(gEngineHandle);
        gEngineHandle = NULL;
    }
}

#pragma endregion

#pragma region Callout Registration

NTSTATUS RegisterWfpCallout(PDEVICE_OBJECT DevObj) {
    UNREFERENCED_PARAMETER(DevObj);

    NTSTATUS Status;
    FWPS_CALLOUT Callout = { 0 };
    FWPM_CALLOUT MgrCallout = { 0 };
    FWPM_SUBLAYER Sublayer = { 0 };

    // Register runtime callout for udp port assignment

    Callout.calloutKey = GUID_PORTMON_CALLOUT; // { 0xb794eefc, 0xdfe1, 0x4f42, { 0x91, 0x68, 0x88, 0xab, 0xa2, 0x79, 0x39, 0x10 } };
    Callout.classifyFn = CalloutClassifyFn;
    Callout.notifyFn = NotifyFn;
    Callout.flowDeleteFn = NULL;  // Add this if you're not using flow deletion

    // register runtime callout
    Status = FwpsCalloutRegister(gDeviceObject, &Callout, &gCalloutId);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to register WFP runtime callout: %08x\n", Status);
        return Status;
    }

    Sublayer.subLayerKey = PORTMON_SUBLAYER;
    Sublayer.displayData.name = L"PortMon Sublayer";
    Sublayer.displayData.description = L"PortMon Sublayer description";
    Sublayer.weight = 0xFFFF; // FWP_EMPTY;

    // Add callout to filter engine
    MgrCallout.calloutKey = Callout.calloutKey;
    MgrCallout.displayData.name = CALLOUT_NAME;
    MgrCallout.displayData.description = CALLOUT_DESC;
    MgrCallout.applicableLayer = FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;

    Status = FwpmCalloutAdd(gEngineHandle, &MgrCallout, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        FwpsCalloutUnregisterById(gCalloutId);
        DbgPrint("Failed to add WFPM callout: %08x\n", Status);
        return Status;
    }

    // add filter
    FWPM_FILTER filter = { 0 };
    filter.layerKey = FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
    filter.displayData.name = CALLOUT_NAME;
    filter.displayData.description = CALLOUT_DESC;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION; //FWP_ACTION_PERMIT;
    filter.action.calloutKey = Callout.calloutKey;

    Status = FwpmFilterAdd(gEngineHandle, &filter, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        FwpsCalloutUnregisterById(gCalloutId);
        DbgPrint("Failed to add WFPM filter: %08x\n", Status);
        return Status;
    }

    // register callout for UDP endpoint closure

    FWPS_CALLOUT ClosureCallout = { 0 };
    // Register runtime callout
    ClosureCallout.calloutKey = GUID_PORTMON_CALLOUT_CLOSURE;
    ClosureCallout.classifyFn = CalloutClassifyFn;
    ClosureCallout.notifyFn = NotifyFn;
    ClosureCallout.flowDeleteFn = NULL;  // Add this if you're not using flow deletion

    // register runtime callout
    Status = FwpsCalloutRegister(gDeviceObject, &ClosureCallout, &gClosureCalloutId);
    if (!NT_SUCCESS(Status)) {
        FwpsCalloutUnregisterById(gCalloutId); // close gCalloutId
        DbgPrint("Failed to register WFP closure runtime callout: %08x\n", Status);
        return Status;
    }

    FWPM_CALLOUT MgrClosureCallout = { 0 };
    // Add callout to filter engine
    MgrClosureCallout.calloutKey = ClosureCallout.calloutKey;
    MgrClosureCallout.displayData.name = CALLOUT_NAME;
    MgrClosureCallout.displayData.description = CALLOUT_DESC;
    MgrClosureCallout.applicableLayer = FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4;

    Status = FwpmCalloutAdd(gEngineHandle, &MgrClosureCallout, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        FwpsCalloutUnregisterById(gCalloutId);
        FwpsCalloutUnregisterById(gClosureCalloutId);
        DbgPrint("Failed to add WFPM closure callout: %08x\n", Status);
        return Status;
    }

    // add filter
    FWPM_FILTER closureFilter = { 0 };
    closureFilter.layerKey = FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4;
    closureFilter.displayData.name = CALLOUT_NAME;
    closureFilter.displayData.description = CALLOUT_DESC;
    closureFilter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    closureFilter.action.calloutKey = ClosureCallout.calloutKey;

    Status = FwpmFilterAdd(gEngineHandle, &closureFilter, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        FwpsCalloutUnregisterById(gCalloutId);
        FwpsCalloutUnregisterById(gClosureCalloutId);
        DbgPrint("Failed to add WFPM closure filter: %08x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

void UnregisterWfpCallout() {
    if (gCalloutId) {
        FwpsCalloutUnregisterById(gCalloutId);
        gCalloutId = 0;
    }
    if (gClosureCalloutId) {
        FwpsCalloutUnregisterById(gClosureCalloutId);
        gClosureCalloutId = 0;
    }
}

#pragma endregion

#pragma region Callout Function Implementation

void NTAPI CalloutClassifyFn(
    const FWPS_INCOMING_VALUES* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT* ClassifyOut
) {
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    UNREFERENCED_PARAMETER(LayerData);

    // DbgPrint("Callout clsfn received layerid: %d, waiting for %d or %d\n", InFixedValues->layerId, FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4);

    if (InFixedValues->layerId != FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4 && InFixedValues->layerId != FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    UINT16 LayerId = InFixedValues->layerId;
    UINT16 Protocol = 0;
    if (LayerId == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4) {
        Protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value.uint16;
    }
    else {
        Protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL].value.uint16;
    }
    UINT16 LocalPort = 0;
    if (LayerId == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4) {
        LocalPort = RtlUshortByteSwap(InFixedValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16);
    }
    else {
        LocalPort = RtlUshortByteSwap(InFixedValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT].value.uint16);
    }
    // identify port assignment / release
    BOOLEAN IsAssignment = (InFixedValues->layerId == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4);

    // DbgPrint("Layerid: %d, Protocol: %d, localPort: %d\n", LayerId, Protocol, LocalPort);

    if (Protocol == IPPROTO_UDP) {
        UINT32 ProcessId = (UINT32)InMetaValues->processId;

        PORT_EVENT Event = { 0 };
        Event.Protocol = Protocol;
        Event.PortNumber = LocalPort;
        Event.ProcessId = ProcessId;
        Event.Timestamp = KeQueryPerformanceCounter(NULL);
        Event.IsAssignment = IsAssignment;

        PushEvent(Event);
        if (IsAssignment) {
            DbgPrint("Captured port assignment: PID=%u, Port=%u\n", ProcessId, LocalPort);
        }
        else {
            DbgPrint("Captured port release: PID=%u, Port=%u\n", ProcessId, LocalPort);
        }
    }
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    //ClassifyOut->actionType = FWP_ACTION_CONTINUE;
}


NTSTATUS NTAPI
NotifyFn(
    IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID* filterKey,
    IN const FWPS_FILTER3* filter
) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

#pragma endregion