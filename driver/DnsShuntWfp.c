#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdmsec.h>
#include <initguid.h>
#include "include/wfp_protocol.h"

#define DNS_SHUNT_DEVICE_NAME L"\\Device\\DnsShuntWfp"
#define DNS_SHUNT_DOS_NAME L"\\DosDevices\\DnsShuntWfp"
#define DNS_SHUNT_POOL_TAG 'sDnD'
#define IPV4_HEADER_SIZE 20u
#define UDP_HEADER_SIZE 8u
#define DNS_SHUNT_ALLOC(Size) ExAllocatePoolWithTag(NonPagedPoolNx, (Size), DNS_SHUNT_POOL_TAG)
#define DNS_SHUNT_AF_INET 2
#define DNS_SHUNT_IPPROTO_UDP 17

DEFINE_GUID(DNS_SHUNT_CALLOUT_KEY,
    0xa232e608, 0x8a6f, 0x4bb9, 0x90, 0x37, 0x25, 0xdf, 0xab, 0xf5, 0x17, 0x6a);

typedef struct _DNS_SHUNT_CAPTURE {
    LIST_ENTRY Link;
    ULONG Length;
    UCHAR Bytes[ANYSIZE_ARRAY];
} DNS_SHUNT_CAPTURE;

typedef struct _DNS_SHUNT_PENDING {
    LIST_ENTRY Link;
    ULONGLONG Token;
    NET_BUFFER_LIST* OriginalNbl;
    UINT32 LocalAddress;
    UINT32 RemoteAddress;
    UINT16 LocalPort;
    UINT16 RemotePort;
    COMPARTMENT_ID CompartmentId;
    IF_INDEX InterfaceIndex;
    IF_INDEX SubInterfaceIndex;
    UINT64 EndpointHandle;
    ULONG RetryCount;
    BOOLEAN Counted;
    BOOLEAN Resolving;
} DNS_SHUNT_PENDING;

typedef struct _DNS_SHUNT_INJECTION {
    DNS_SHUNT_PENDING* Pending;
    NET_BUFFER_LIST* Nbl;
    PMDL Mdl;
    UCHAR* Bytes;
} DNS_SHUNT_INJECTION;

static PDEVICE_OBJECT gDeviceObject;
static NDIS_HANDLE gNblPool;
static HANDLE gInjectionHandle;
static UINT32 gCalloutId;
static KSPIN_LOCK gLock;
static LIST_ENTRY gPending;
static LIST_ENTRY gCaptures;
static KSEMAPHORE gCaptureAvailable;
static KEVENT gNoInflightInjection;
static ULONG gPendingCount;
static LONG gInflightInjections;
static volatile LONG gControllerOpen;
static volatile LONG gStopping;
static volatile LONG gShutdownWakePosted;
static volatile LONG64 gNextToken = 1;

static VOID DnsShuntClassify(
    const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut);
static VOID DnsShuntInjectComplete(VOID* Context, NET_BUFFER_LIST* Nbl, BOOLEAN DispatchLevel);
static VOID DnsShuntResponseComplete(VOID* Context, NET_BUFFER_LIST* Nbl, BOOLEAN DispatchLevel);
static NTSTATUS DnsShuntInjectOriginal(_In_ DNS_SHUNT_PENDING* Pending);

static VOID
DnsShuntBeginInjection(VOID)
{
    KIRQL Irql;
    KeAcquireSpinLock(&gLock, &Irql);
    if (gInflightInjections == 0)
        KeClearEvent(&gNoInflightInjection);
    ++gInflightInjections;
    KeReleaseSpinLock(&gLock, Irql);
}

static VOID
DnsShuntBeginInjectionLocked(VOID)
{
    if (gInflightInjections == 0)
        KeClearEvent(&gNoInflightInjection);
    ++gInflightInjections;
}

static VOID
DnsShuntEndInjection(VOID)
{
    KIRQL Irql;
    KeAcquireSpinLock(&gLock, &Irql);
    if (--gInflightInjections == 0)
        KeSetEvent(&gNoInflightInjection, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&gLock, Irql);
}

static ULONG
Checksum(_In_reads_bytes_(Length) const UCHAR* Bytes, ULONG Length)
{
    ULONG Sum = 0;
    ULONG Index;
    for (Index = 0; Index + 1 < Length; Index += 2)
        Sum += ((ULONG)Bytes[Index] << 8) | Bytes[Index + 1];
    if ((Length & 1) != 0)
        Sum += (ULONG)Bytes[Length - 1] << 8;
    while ((Sum >> 16) != 0)
        Sum = (Sum & 0xffff) + (Sum >> 16);
    return (~Sum) & 0xffff;
}

static VOID
DnsShuntFreeCapture(_In_opt_ DNS_SHUNT_CAPTURE* Capture)
{
    if (Capture != NULL)
        ExFreePoolWithTag(Capture, DNS_SHUNT_POOL_TAG);
}

static VOID
DnsShuntReleasePending(_In_ DNS_SHUNT_PENDING* Pending, _In_ BOOLEAN DispatchLevel)
{
    if (Pending->Counted) {
        KIRQL Irql;
        KeAcquireSpinLock(&gLock, &Irql);
        if (Pending->Counted) {
            Pending->Counted = FALSE;
            --gPendingCount;
        }
        KeReleaseSpinLock(&gLock, Irql);
    }
    if (Pending->OriginalNbl != NULL)
        FwpsDereferenceNetBufferList0(Pending->OriginalNbl, DispatchLevel);
    ExFreePoolWithTag(Pending, DNS_SHUNT_POOL_TAG);
}

static DNS_SHUNT_PENDING*
DnsShuntFindPendingLocked(ULONGLONG Token)
{
    PLIST_ENTRY Link;
    for (Link = gPending.Flink; Link != &gPending; Link = Link->Flink) {
        DNS_SHUNT_PENDING* Pending = CONTAINING_RECORD(Link, DNS_SHUNT_PENDING, Link);
        if (Pending->Token == Token)
            return Pending;
    }
    return NULL;
}

static VOID
DnsShuntPermit(_Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
}

static VOID
DnsShuntClassify(
    const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    NET_BUFFER_LIST* Nbl = (NET_BUFFER_LIST*)LayerData;
    NET_BUFFER* Nb;
    ULONG PacketLength;
    ULONG UdpLength;
    ULONG PayloadLength;
    UCHAR* Scratch = NULL;
    UCHAR* PacketBytes;
    DNS_SHUNT_PENDING* Pending = NULL;
    DNS_SHUNT_CAPTURE* Capture = NULL;
    KIRQL Irql;
    ULONG SourceAddress;
    ULONG DestinationAddress;
    UINT16 SourcePort;
    UINT16 DestinationPort;
    FWPS_PACKET_INJECTION_STATE InjectionState;
    UNREFERENCED_PARAMETER(FlowContext);
    UNREFERENCED_PARAMETER(Filter);

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;
    if (Nbl == NULL || InterlockedCompareExchange(&gStopping, 0, 0) != 0) {
        DnsShuntPermit(ClassifyOut);
        return;
    }
    InjectionState = FwpsQueryPacketInjectionState0(gInjectionHandle, Nbl, NULL);
    if (InjectionState == FWPS_PACKET_INJECTED_BY_SELF ||
        InjectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        DnsShuntPermit(ClassifyOut);
        return;
    }
    if (!FWPS_IS_METADATA_FIELD_PRESENT(Metadata, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) ||
        !FWPS_IS_METADATA_FIELD_PRESENT(Metadata, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        DnsShuntPermit(ClassifyOut);
        return;
    }

    Nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    if (Nb == NULL) {
        DnsShuntPermit(ClassifyOut);
        return;
    }
    PacketLength = NET_BUFFER_DATA_LENGTH(Nb);
    if (PacketLength < UDP_HEADER_SIZE)
        goto Permit;
    Scratch = DNS_SHUNT_ALLOC(PacketLength);
    if (Scratch == NULL)
        goto Permit;
    PacketBytes = NdisGetDataBuffer(Nb, PacketLength, Scratch, 1, 0);
    if (PacketBytes == NULL)
        goto Permit;
    UdpLength = ((ULONG)PacketBytes[4] << 8) | PacketBytes[5];
    if (UdpLength < UDP_HEADER_SIZE || UdpLength > PacketLength)
        goto Permit;
    PayloadLength = UdpLength - UDP_HEADER_SIZE;
    if (PayloadLength > DNS_SHUNT_MAX_DNS_PAYLOAD)
        goto Permit;

    SourceAddress = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
    DestinationAddress = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
    SourcePort = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
    DestinationPort = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
    if (DestinationPort != 53)
        goto Permit;

    Pending = DNS_SHUNT_ALLOC(sizeof(*Pending));
    Capture = DNS_SHUNT_ALLOC(
        FIELD_OFFSET(DNS_SHUNT_CAPTURE, Bytes) + sizeof(DNS_SHUNT_CAPTURE_HEADER) + PayloadLength);
    if (Pending == NULL || Capture == NULL)
        goto Permit;
    RtlZeroMemory(Pending, sizeof(*Pending));
    Pending->Token = (ULONGLONG)InterlockedIncrement64(&gNextToken);
    Pending->LocalAddress = RtlUlongByteSwap(SourceAddress);
    Pending->RemoteAddress = RtlUlongByteSwap(DestinationAddress);
    Pending->LocalPort = RtlUshortByteSwap(SourcePort);
    Pending->RemotePort = RtlUshortByteSwap(DestinationPort);
    Pending->CompartmentId = Metadata->compartmentId;
    Pending->EndpointHandle = Metadata->transportEndpointHandle;
    Pending->InterfaceIndex = Values->incomingValue[
        FWPS_FIELD_OUTBOUND_TRANSPORT_V4_INTERFACE_INDEX].value.uint32;
    Pending->SubInterfaceIndex = Values->incomingValue[
        FWPS_FIELD_OUTBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX].value.uint32;
    Pending->OriginalNbl = Nbl;
    FwpsReferenceNetBufferList0(Nbl, TRUE);

    Capture->Length = sizeof(DNS_SHUNT_CAPTURE_HEADER) + PayloadLength;
    {
        DNS_SHUNT_CAPTURE_HEADER* Header = (DNS_SHUNT_CAPTURE_HEADER*)Capture->Bytes;
        Header->Magic = DNS_SHUNT_PROTOCOL_MAGIC;
        Header->Version = DNS_SHUNT_PROTOCOL_VERSION;
        Header->HeaderLength = (UINT16)sizeof(*Header);
        Header->TotalLength = Capture->Length;
        Header->PayloadLength = PayloadLength;
        Header->Token = Pending->Token;
        RtlCopyMemory(Header->SourceAddress, &Pending->LocalAddress, 4);
        RtlCopyMemory(Header->DestinationAddress, &Pending->RemoteAddress, 4);
        Header->SourcePort = SourcePort;
        Header->DestinationPort = DestinationPort;
        if (PayloadLength != 0)
            RtlCopyMemory(Capture->Bytes + sizeof(*Header), PacketBytes + UDP_HEADER_SIZE, PayloadLength);
    }

    KeAcquireSpinLock(&gLock, &Irql);
    if (gPendingCount >= DNS_SHUNT_MAX_PENDING ||
        InterlockedCompareExchange(&gStopping, 0, 0) != 0) {
        KeReleaseSpinLock(&gLock, Irql);
        FwpsDereferenceNetBufferList0(Nbl, TRUE);
        Pending->OriginalNbl = NULL;
        goto Permit;
    }
    InsertTailList(&gPending, &Pending->Link);
    InsertTailList(&gCaptures, &Capture->Link);
    Pending->Counted = TRUE;
    ++gPendingCount;
    KeReleaseSpinLock(&gLock, Irql);
    KeReleaseSemaphore(&gCaptureAvailable, IO_NO_INCREMENT, 1, FALSE);

    Pending = NULL;
    Capture = NULL;
    ClassifyOut->actionType = FWP_ACTION_BLOCK;
    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    ClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    if (Scratch != NULL)
        ExFreePoolWithTag(Scratch, DNS_SHUNT_POOL_TAG);
    return;

Permit:
    if (Pending != NULL) {
        if (Pending->OriginalNbl != NULL)
            FwpsDereferenceNetBufferList0(Pending->OriginalNbl, TRUE);
        ExFreePoolWithTag(Pending, DNS_SHUNT_POOL_TAG);
    }
    DnsShuntFreeCapture(Capture);
    if (Scratch != NULL)
        ExFreePoolWithTag(Scratch, DNS_SHUNT_POOL_TAG);
    DnsShuntPermit(ClassifyOut);
}

static VOID
DnsShuntInjectComplete(VOID* Context, NET_BUFFER_LIST* Nbl, BOOLEAN DispatchLevel)
{
    DNS_SHUNT_PENDING* Pending = (DNS_SHUNT_PENDING*)Context;
    if (!NT_SUCCESS(NET_BUFFER_LIST_STATUS(Nbl)) && Pending->RetryCount == 0) {
        ++Pending->RetryCount;
        FwpsFreeCloneNetBufferList0(Nbl, 0);
        if (NT_SUCCESS(DnsShuntInjectOriginal(Pending))) {
            DnsShuntEndInjection();
            return;
        }
        DnsShuntReleasePending(Pending, DispatchLevel);
        DnsShuntEndInjection();
        return;
    }
    FwpsFreeCloneNetBufferList0(Nbl, 0);
    DnsShuntReleasePending(Pending, DispatchLevel);
    DnsShuntEndInjection();
}

static NTSTATUS
DnsShuntInjectOriginal(_In_ DNS_SHUNT_PENDING* Pending)
{
    NET_BUFFER_LIST* Clone = NULL;
    FWPS_TRANSPORT_SEND_PARAMS0 SendParams;
    NTSTATUS Status;
    RtlZeroMemory(&SendParams, sizeof(SendParams));
    Status = FwpsAllocateCloneNetBufferList0(Pending->OriginalNbl, NULL, NULL, 0, &Clone);
    if (!NT_SUCCESS(Status))
        return Status;
    SendParams.remoteAddress = (UINT8*)&Pending->RemoteAddress;
    DnsShuntBeginInjection();
    Status = FwpsInjectTransportSendAsync0(
        gInjectionHandle, NULL, Pending->EndpointHandle, 0, &SendParams,
        DNS_SHUNT_AF_INET, Pending->CompartmentId, Clone, DnsShuntInjectComplete, Pending);
    if (!NT_SUCCESS(Status)) {
        FwpsFreeCloneNetBufferList0(Clone, 0);
        DnsShuntEndInjection();
    }
    return Status;
}

static NTSTATUS
DnsShuntInjectResponse(_In_ DNS_SHUNT_PENDING* Pending, _In_reads_bytes_(PayloadLength) const UCHAR* Payload,
                       _In_ ULONG PayloadLength)
{
    ULONG TotalLength = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + PayloadLength;
    ULONG UdpLength = UDP_HEADER_SIZE + PayloadLength;
    DNS_SHUNT_INJECTION* Injection;
    UCHAR* Ip;
    UCHAR* Udp;
    UCHAR Pseudo[12];
    ULONG UdpChecksum;
    NTSTATUS Status;
    if (PayloadLength > DNS_SHUNT_MAX_DNS_PAYLOAD)
        return STATUS_INVALID_BUFFER_SIZE;
    Injection = DNS_SHUNT_ALLOC(sizeof(*Injection));
    if (Injection == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Injection, sizeof(*Injection));
    Injection->Bytes = DNS_SHUNT_ALLOC(TotalLength);
    if (Injection->Bytes == NULL) {
        ExFreePoolWithTag(Injection, DNS_SHUNT_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Injection->Bytes, TotalLength);
    Ip = Injection->Bytes;
    Udp = Ip + IPV4_HEADER_SIZE;
    Ip[0] = 0x45;
    Ip[2] = (UCHAR)(TotalLength >> 8);
    Ip[3] = (UCHAR)TotalLength;
    Ip[6] = 0x40;
    Ip[8] = 64;
    Ip[9] = DNS_SHUNT_IPPROTO_UDP;
    RtlCopyMemory(Ip + 12, &Pending->RemoteAddress, 4);
    RtlCopyMemory(Ip + 16, &Pending->LocalAddress, 4);
    {
        ULONG Check = Checksum(Ip, IPV4_HEADER_SIZE);
        Ip[10] = (UCHAR)(Check >> 8);
        Ip[11] = (UCHAR)Check;
    }
    RtlCopyMemory(Udp, &Pending->RemotePort, 2);
    RtlCopyMemory(Udp + 2, &Pending->LocalPort, 2);
    Udp[4] = (UCHAR)(UdpLength >> 8);
    Udp[5] = (UCHAR)UdpLength;
    if (PayloadLength != 0)
        RtlCopyMemory(Udp + UDP_HEADER_SIZE, Payload, PayloadLength);
    RtlCopyMemory(Pseudo, Ip + 12, 8);
    Pseudo[8] = 0;
    Pseudo[9] = DNS_SHUNT_IPPROTO_UDP;
    Pseudo[10] = (UCHAR)(UdpLength >> 8);
    Pseudo[11] = (UCHAR)UdpLength;
    {
        UCHAR* CheckBytes = DNS_SHUNT_ALLOC(sizeof(Pseudo) + UdpLength);
        if (CheckBytes == NULL) {
            ExFreePoolWithTag(Injection->Bytes, DNS_SHUNT_POOL_TAG);
            ExFreePoolWithTag(Injection, DNS_SHUNT_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(CheckBytes, Pseudo, sizeof(Pseudo));
        RtlCopyMemory(CheckBytes + sizeof(Pseudo), Udp, UdpLength);
        UdpChecksum = Checksum(CheckBytes, sizeof(Pseudo) + UdpLength);
        ExFreePoolWithTag(CheckBytes, DNS_SHUNT_POOL_TAG);
        if (UdpChecksum == 0)
            UdpChecksum = 0xffff;
    }
    Udp[6] = (UCHAR)(UdpChecksum >> 8);
    Udp[7] = (UCHAR)UdpChecksum;

    Injection->Mdl = IoAllocateMdl(Injection->Bytes, TotalLength, FALSE, FALSE, NULL);
    if (Injection->Mdl == NULL) {
        ExFreePoolWithTag(Injection->Bytes, DNS_SHUNT_POOL_TAG);
        ExFreePoolWithTag(Injection, DNS_SHUNT_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Injection->Mdl);
    Injection->Nbl = NdisAllocateNetBufferAndNetBufferList(gNblPool, 0, 0, Injection->Mdl, 0, TotalLength);
    if (Injection->Nbl == NULL) {
        IoFreeMdl(Injection->Mdl);
        ExFreePoolWithTag(Injection->Bytes, DNS_SHUNT_POOL_TAG);
        ExFreePoolWithTag(Injection, DNS_SHUNT_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Injection->Pending = Pending;
    DnsShuntBeginInjection();
    Status = FwpsInjectTransportReceiveAsync0(
        gInjectionHandle, NULL, NULL, 0, DNS_SHUNT_AF_INET, Pending->CompartmentId,
        Pending->InterfaceIndex, Pending->SubInterfaceIndex,
        Injection->Nbl, DnsShuntResponseComplete, Injection);
    if (!NT_SUCCESS(Status)) {
        DnsShuntEndInjection();
        NdisFreeNetBufferList(Injection->Nbl);
        IoFreeMdl(Injection->Mdl);
        ExFreePoolWithTag(Injection->Bytes, DNS_SHUNT_POOL_TAG);
        ExFreePoolWithTag(Injection, DNS_SHUNT_POOL_TAG);
    }
    return Status;
}

static VOID
DnsShuntResponseComplete(VOID* Context, NET_BUFFER_LIST* Nbl, BOOLEAN DispatchLevel)
{
    DNS_SHUNT_INJECTION* Injection = (DNS_SHUNT_INJECTION*)Context;
    DNS_SHUNT_PENDING* Pending = Injection->Pending;
    UNREFERENCED_PARAMETER(DispatchLevel);
    if (NT_SUCCESS(NET_BUFFER_LIST_STATUS(Nbl))) {
        DnsShuntReleasePending(Pending, DispatchLevel);
    } else {
        if (!NT_SUCCESS(DnsShuntInjectOriginal(Pending)))
            DnsShuntReleasePending(Pending, DispatchLevel);
    }
    NdisFreeNetBufferList(Nbl);
    IoFreeMdl(Injection->Mdl);
    ExFreePoolWithTag(Injection->Bytes, DNS_SHUNT_POOL_TAG);
    ExFreePoolWithTag(Injection, DNS_SHUNT_POOL_TAG);
    DnsShuntEndInjection();
}

static NTSTATUS
DnsShuntResolve(_In_reads_bytes_(InputLength) const UCHAR* Input, _In_ ULONG InputLength)
{
    const DNS_SHUNT_COMMAND_HEADER* Header;
    DNS_SHUNT_PENDING* Pending;
    KIRQL Irql;
    NTSTATUS Status;
    ULONG Expected;
    if (InputLength < sizeof(DNS_SHUNT_COMMAND_HEADER))
        return STATUS_BUFFER_TOO_SMALL;
    Header = (const DNS_SHUNT_COMMAND_HEADER*)Input;
    if (Header->Magic != DNS_SHUNT_PROTOCOL_MAGIC || Header->Version != DNS_SHUNT_PROTOCOL_VERSION ||
        Header->TotalLength != InputLength || Header->PayloadLength > DNS_SHUNT_MAX_DNS_PAYLOAD ||
        Header->TotalLength != sizeof(*Header) + Header->PayloadLength)
        return STATUS_INVALID_PARAMETER;
    Expected = (Header->Command == DNS_SHUNT_COMMAND_RESPONSE) ? Header->PayloadLength : 0;
    if ((Header->Command != DNS_SHUNT_COMMAND_REINJECT && Header->Command != DNS_SHUNT_COMMAND_RESPONSE) ||
        Expected != Header->PayloadLength)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&gLock, &Irql);
    Pending = DnsShuntFindPendingLocked(Header->Token);
    if (Pending == NULL || Pending->Resolving) {
        KeReleaseSpinLock(&gLock, Irql);
        return STATUS_NOT_FOUND;
    }
    Pending->Resolving = TRUE;
    RemoveEntryList(&Pending->Link);
    DnsShuntBeginInjectionLocked();
    KeReleaseSpinLock(&gLock, Irql);

    if (Header->Command == DNS_SHUNT_COMMAND_REINJECT)
        Status = DnsShuntInjectOriginal(Pending);
    else
        Status = DnsShuntInjectResponse(Pending, Input + sizeof(*Header), Header->PayloadLength);
    if (!NT_SUCCESS(Status)) {
        BOOLEAN FailOpen = FALSE;
        KeAcquireSpinLock(&gLock, &Irql);
        if (InterlockedCompareExchange(&gStopping, 0, 0) != 0) {
            FailOpen = TRUE;
        } else {
            Pending->Resolving = FALSE;
            InsertTailList(&gPending, &Pending->Link);
        }
        KeReleaseSpinLock(&gLock, Irql);
        if (FailOpen && !NT_SUCCESS(DnsShuntInjectOriginal(Pending)))
            DnsShuntReleasePending(Pending, FALSE);
        DnsShuntEndInjection();
        return Status;
    }

    DnsShuntEndInjection();
    return STATUS_SUCCESS;
}

static NTSTATUS
DnsShuntRead(_Inout_ PIRP Irp, _In_ ULONG OutputLength)
{
    LARGE_INTEGER Timeout;
    DNS_SHUNT_CAPTURE* Capture;
    KIRQL Irql;
    NTSTATUS Status;
    Timeout.QuadPart = -1000000;
    for (;;) {
        if (Irp->Cancel)
            return STATUS_CANCELLED;
        Status = KeWaitForSingleObject(&gCaptureAvailable, Executive, KernelMode, FALSE, &Timeout);
        if (Status != STATUS_SUCCESS && Status != STATUS_TIMEOUT)
            return Status;
        KeAcquireSpinLock(&gLock, &Irql);
        if (!IsListEmpty(&gCaptures)) {
            PLIST_ENTRY Link = RemoveHeadList(&gCaptures);
            Capture = CONTAINING_RECORD(Link, DNS_SHUNT_CAPTURE, Link);
            KeReleaseSpinLock(&gLock, Irql);
            if (OutputLength < Capture->Length) {
                Irp->IoStatus.Information = Capture->Length;
                DnsShuntFreeCapture(Capture);
                return STATUS_BUFFER_TOO_SMALL;
            }
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, Capture->Bytes, Capture->Length);
            Irp->IoStatus.Information = Capture->Length;
            DnsShuntFreeCapture(Capture);
            return STATUS_SUCCESS;
        }
        KeReleaseSpinLock(&gLock, Irql);
        if (InterlockedCompareExchange(&gStopping, 0, 0) != 0)
            return STATUS_CANCELLED;
    }
}

static NTSTATUS
DnsShuntCreate(_In_ PIRP Irp)
{
    if (InterlockedCompareExchange(&gControllerOpen, 1, 0) != 0)
        return STATUS_SHARING_VIOLATION;
    InterlockedExchange(&gStopping, 0);
    InterlockedExchange(&gShutdownWakePosted, 0);
    UNREFERENCED_PARAMETER(Irp);
    return STATUS_SUCCESS;
}

static VOID
DnsShuntCleanup(_In_ PIRP Irp)
{
    LIST_ENTRY PendingList;
    LIST_ENTRY CaptureList;
    KIRQL Irql;
    LARGE_INTEGER Timeout;
    LARGE_INTEGER Timeout;
    UNREFERENCED_PARAMETER(Irp);
    InitializeListHead(&PendingList);
    InitializeListHead(&CaptureList);
    InterlockedExchange(&gStopping, 1);
    if (InterlockedExchange(&gShutdownWakePosted, 1) == 0)
        KeReleaseSemaphore(&gCaptureAvailable, IO_NO_INCREMENT, 1, FALSE);
    KeWaitForSingleObject(&gNoInflightInjection, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&gLock, &Irql);
    while (!IsListEmpty(&gPending))
        InsertTailList(&PendingList, RemoveHeadList(&gPending));
    while (!IsListEmpty(&gCaptures))
        InsertTailList(&CaptureList, RemoveHeadList(&gCaptures));
    KeReleaseSpinLock(&gLock, Irql);
    Timeout.QuadPart = 0;
    while (KeWaitForSingleObject(&gCaptureAvailable, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS) {}
    while (!IsListEmpty(&CaptureList)) {
        DNS_SHUNT_CAPTURE* Capture = CONTAINING_RECORD(RemoveHeadList(&CaptureList), DNS_SHUNT_CAPTURE, Link);
        DnsShuntFreeCapture(Capture);
    }
    while (!IsListEmpty(&PendingList)) {
        DNS_SHUNT_PENDING* Pending = CONTAINING_RECORD(RemoveHeadList(&PendingList), DNS_SHUNT_PENDING, Link);
        if (!NT_SUCCESS(DnsShuntInjectOriginal(Pending)))
            DnsShuntReleasePending(Pending, FALSE);
    }
    KeWaitForSingleObject(&gNoInflightInjection, Executive, KernelMode, FALSE, NULL);
    InterlockedExchange(&gControllerOpen, 0);
}

static NTSTATUS
DnsShuntDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR Information = 0;
    UNREFERENCED_PARAMETER(DeviceObject);
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
        Status = DnsShuntCreate(Irp);
        break;
    case IRP_MJ_CLEANUP:
        DnsShuntCleanup(Irp);
        Status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        Status = STATUS_SUCCESS;
        break;
    case IRP_MJ_READ:
        Irp->IoStatus.Information = 0;
        Status = DnsShuntRead(Irp, Stack->Parameters.Read.Length);
        Information = Irp->IoStatus.Information;
        break;
    case IRP_MJ_DEVICE_CONTROL:
        if (Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DNS_SHUNT_RESOLVE) {
            Status = DnsShuntResolve(
                (const UCHAR*)Irp->AssociatedIrp.SystemBuffer,
                Stack->Parameters.DeviceIoControl.InputBufferLength);
        } else if (Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DNS_SHUNT_SHUTDOWN) {
            InterlockedExchange(&gStopping, 1);
            if (InterlockedExchange(&gShutdownWakePosted, 1) == 0)
                KeReleaseSemaphore(&gCaptureAvailable, IO_NO_INCREMENT, 1, FALSE);
            Status = STATUS_SUCCESS;
        }
        break;
    }
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
DnsShuntRegisterCallout(_In_ PDEVICE_OBJECT DeviceObject)
{
    FWPS_CALLOUT0 Callout;
    RtlZeroMemory(&Callout, sizeof(Callout));
    Callout.calloutKey = DNS_SHUNT_CALLOUT_KEY;
    Callout.classifyFn = DnsShuntClassify;
    return FwpsCalloutRegister0(DeviceObject, &Callout, &gCalloutId);
}

static VOID
DnsShuntUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosName = RTL_CONSTANT_STRING(DNS_SHUNT_DOS_NAME);
    UNREFERENCED_PARAMETER(DriverObject);
    DnsShuntCleanup(NULL);
    if (gCalloutId != 0)
        FwpsCalloutUnregisterById0(gCalloutId);
    if (gInjectionHandle != NULL)
        FwpsInjectionHandleDestroy0(gInjectionHandle);
    if (gNblPool != NULL)
        NdisFreeNetBufferListPool(gNblPool);
    IoDeleteSymbolicLink(&DosName);
    if (gDeviceObject != NULL)
        IoDeleteDevice(gDeviceObject);
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DNS_SHUNT_DEVICE_NAME);
    UNICODE_STRING DosName = RTL_CONSTANT_STRING(DNS_SHUNT_DOS_NAME);
    UNICODE_STRING Sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NDIS_NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
    ULONG Index;
    UNREFERENCED_PARAMETER(RegistryPath);
    InitializeListHead(&gPending);
    InitializeListHead(&gCaptures);
    KeInitializeSpinLock(&gLock);
    KeInitializeSemaphore(&gCaptureAvailable, 0, DNS_SHUNT_MAX_PENDING + 1);
    KeInitializeEvent(&gNoInflightInjection, NotificationEvent, TRUE);
    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; ++Index)
        DriverObject->MajorFunction[Index] = DnsShuntDispatch;
    DriverObject->DriverUnload = DnsShuntUnload;

    Status = IoCreateDeviceSecure(
        DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &Sddl, NULL, &gDeviceObject);
    if (!NT_SUCCESS(Status))
        return Status;
    gDeviceObject->Flags |= DO_BUFFERED_IO;
    Status = IoCreateSymbolicLink(&DosName, &DeviceName);
    if (!NT_SUCCESS(Status))
        goto Failure;

    RtlZeroMemory(&PoolParameters, sizeof(PoolParameters));
    PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    PoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    PoolParameters.fAllocateNetBuffer = TRUE;
    PoolParameters.PoolTag = DNS_SHUNT_POOL_TAG;
    gNblPool = NdisAllocateNetBufferListPool(NULL, &PoolParameters);
    if (gNblPool == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }
    Status = FwpsInjectionHandleCreate0(DNS_SHUNT_AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &gInjectionHandle);
    if (!NT_SUCCESS(Status))
        goto Failure;
    Status = DnsShuntRegisterCallout(gDeviceObject);
    if (!NT_SUCCESS(Status))
        goto Failure;
    gDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;

Failure:
    DnsShuntUnload(DriverObject);
    return Status;
}
