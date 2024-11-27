#include <ntddk.h>
#include <initguid.h>
#define NDIS_SUPPORT_NDIS6 1
#pragma warning(disable:4201)  // Disable warning about nameless struct/union
#include <ndis.h> // Network Driver Interface definitions (defines NET_BUFFER_LIST)
#pragma warning(default:4201)  // Re-enable the warning after the include 
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>


// Define {d700f2c9-cc76-4d99-9364-475dbfd8b35b}
DEFINE_GUID(GUID_PORTMON_CALLOUT, 0xd700f2c9, 0xcc76, 0x4d99, 0x93, 0x64, 0x47, 0x5d, 0xbf, 0xd8, 0xb3, 0x5b);

#define WFP_LAYER ALE_BIND_REDIRECT_V4
#define CALLOUT_NAME L"WFP Port Monitoring Callout"
#define CALLOUT_DESC L"Monitors local port assignment and release events."

#define IOCTL_GET_PORT_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define DEVICE_NAME L"\\Device\\PortMonDriver"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\PortMonDriver"


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
    KEVENT EventAvailable; // Signaling event
    FAST_MUTEX Mutex;      // Protect shared resources
} EVENT_QUEUE, * PEVENT_QUEUE;

static EVENT_QUEUE EventQueue;
static PDEVICE_OBJECT DeviceObject = NULL;
static UNICODE_STRING SymbolicLinkName;
static HANDLE EngineHandle = NULL;
static UINT32 CalloutId = 0;


#pragma region WFP Helper Functions and Structures

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

#pragma endregion

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void PushEvent(PORT_EVENT Event);
NTSTATUS MonitorPortEvents(); // Placeholder for WFP implementation
void StopMonitoringPortEvents();

#pragma region Event Queue Implementation

void InitializeEventQueue() {
    EventQueue.Head = 0;
    EventQueue.Tail = 0;
    KeInitializeEvent(&EventQueue.EventAvailable, NotificationEvent, FALSE);
    ExInitializeFastMutex(&EventQueue.Mutex);
}

void PushEvent(PORT_EVENT Event) {
    ExAcquireFastMutex(&EventQueue.Mutex);

    ULONG nextTail = (EventQueue.Tail + 1) % MAX_EVENTS;

    if (nextTail != EventQueue.Head) {
        EventQueue.Events[EventQueue.Tail] = Event;
        EventQueue.Tail = nextTail;
        KeSetEvent(&EventQueue.EventAvailable, 0, FALSE);
    }
    else {
        DbgPrint("Event queue overflow, dropping event\n");
    }

    ExReleaseFastMutex(&EventQueue.Mutex);
}

#pragma endregion

#pragma region Driver Entry and Unload

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;
    UNICODE_STRING DeviceName;

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&SymbolicLinkName, SYMBOLIC_LINK_NAME);

    Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to create device: %08x\n", Status);
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to create symbolic link: %08x\n", Status);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    InitializeEventQueue();

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlHandler;
    DriverObject->DriverUnload = DriverUnload;

    // Start monitoring port events
    Status = MonitorPortEvents();
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to start WFP monitoring: %08x\n", Status);
        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DbgPrint("Driver initialized successfully\n");
    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DevObj) {
    UNREFERENCED_PARAMETER(DevObj);
    StopMonitoringPortEvents();

    IoDeleteSymbolicLink(&SymbolicLinkName);
    IoDeleteDevice(DeviceObject);

    DbgPrint("Driver unloaded successfully\n");
}

#pragma endregion

#pragma region IRP Handlers

NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IoControlHandler(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);

    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesTransferred = 0;

    if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_PORT_EVENTS) {
        // Wait for an event to be available
        NTSTATUS WaitStatus = KeWaitForSingleObject(&EventQueue.EventAvailable, Executive, KernelMode, FALSE, NULL);

        if (WaitStatus == STATUS_SUCCESS) {
            // Fetch events from the queue
            PPORT_EVENT Buffer = (PPORT_EVENT)Irp->AssociatedIrp.SystemBuffer;
            ULONG Count = 0;

            ExAcquireFastMutex(&EventQueue.Mutex);

            while (EventQueue.Head != EventQueue.Tail && Count < IoStack->Parameters.DeviceIoControl.OutputBufferLength / sizeof(PORT_EVENT)) {
                Buffer[Count++] = EventQueue.Events[EventQueue.Head];
                EventQueue.Head = (EventQueue.Head + 1) % MAX_EVENTS;
            }

            if (EventQueue.Head == EventQueue.Tail) {
                // reset head and tail
                EventQueue.Head = 0;
                EventQueue.Tail = 0;
                KeResetEvent(&EventQueue.EventAvailable);
            }

            ExReleaseFastMutex(&EventQueue.Mutex);
            BytesTransferred = Count * sizeof(PORT_EVENT);
        }
        else {
            Status = STATUS_TIMEOUT;
        }
    }
    else {
        Status = STATUS_INVALID_DEVICE_REQUEST;
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

    Status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &Session, &EngineHandle);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to open WFP engine: %08x\n", Status);
        return Status;
    }

    Status = RegisterWfpCallout(DeviceObject);
    if (!NT_SUCCESS(Status)) {
        FwpmEngineClose(EngineHandle);
        EngineHandle = NULL;
        DbgPrint("Failed to register WFP callout: %08x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

void StopMonitoringPortEvents() {
    UnregisterWfpCallout();

    if (EngineHandle) {
        FwpmEngineClose(EngineHandle);
        EngineHandle = NULL;
    }
}

#pragma endregion

#pragma region Callout Registration

NTSTATUS RegisterWfpCallout(PDEVICE_OBJECT DevObj) {
    UNREFERENCED_PARAMETER(DevObj);

    NTSTATUS Status;
    FWPS_CALLOUT Callout = { 0 };
    FWPM_CALLOUT MgrCallout = { 0 };

    // Register runtime callout
    Callout.calloutKey = GUID_PORTMON_CALLOUT; // { 0xb794eefc, 0xdfe1, 0x4f42, { 0x91, 0x68, 0x88, 0xab, 0xa2, 0x79, 0x39, 0x10 } };
    Callout.classifyFn = CalloutClassifyFn;
    Callout.notifyFn = NULL;
    Callout.flowDeleteFn = NULL;  // Add this if you're not using flow deletion

    Status = FwpsCalloutRegister(DeviceObject, &Callout, &CalloutId);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("Failed to register WFP runtime callout: %08x\n", Status);
        return Status;
    }

    // Add callout to filter engine
    MgrCallout.calloutKey = Callout.calloutKey;
    MgrCallout.displayData.name = CALLOUT_NAME;
    MgrCallout.displayData.description = CALLOUT_DESC;
    MgrCallout.applicableLayer = FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;

    Status = FwpmCalloutAdd(EngineHandle, &MgrCallout, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        FwpsCalloutUnregisterById(CalloutId);
        DbgPrint("Failed to add WFP callout: %08x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

void UnregisterWfpCallout() {
    if (CalloutId) {
        FwpsCalloutUnregisterById(CalloutId);
        CalloutId = 0;
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

    if (InFixedValues->layerId != FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    UINT16 Protocol = InFixedValues->incomingValue[FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value.uint16;
    if (Protocol == IPPROTO_UDP){
        UINT16 LocalPort = RtlUshortByteSwap(InFixedValues->incomingValue[FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16);
        UINT32 ProcessId = (UINT32)InMetaValues->processId;

        // TODO: identify port assignment / release
        BOOLEAN IsAssignment = (InFixedValues->layerId == FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4);

        PORT_EVENT Event = { 0 };
        Event.Protocol = Protocol;
        Event.PortNumber = LocalPort;
        Event.ProcessId = ProcessId;
        Event.Timestamp = KeQueryPerformanceCounter(NULL);
        Event.IsAssignment = IsAssignment ? TRUE : FALSE; //

        PushEvent(Event);
        if (IsAssignment) {
            DbgPrint("Captured port assignment: PID=%u, Port=%u\n", ProcessId, LocalPort);
        }
        else {
            DbgPrint("Captured port release: PID=%u, Port=%u\n", ProcessId, LocalPort);
        }
    }
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
}

#pragma endregion