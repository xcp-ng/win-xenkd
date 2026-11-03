#include "xenkd.h"

PKDNET_EXTENSIBILITY_IMPORTS KdNetExtensibilityImports;

static USHORT XenKdIoPort = XENKD_DEFAULT_IO_PORT;

// Without a heartbeat from dom0 for XENKD_DOM0_TIMEOUT_S, it's detached. While detached, the shared area is announced
// through the I/O port every XENKD_ANNOUNCE_INTERVAL_S.
#define XENKD_DOM0_TIMEOUT_S 2
#define XENKD_ANNOUNCE_INTERVAL_S 1

// When the TX ring is full, poll it every XENKD_TX_STALL_US, and give up on the frame after XENKD_TX_TIMEOUT_MS.
#define XENKD_TX_STALL_US 10
#define XENKD_TX_TIMEOUT_MS 100

_IRQL_requires_same_ _IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return STATUS_SUCCESS;
}

// Report why initialization failed. KDNET stores these in the registry (Services\kdnet) for diagnosis.
static NTSTATUS XenKdFail(_In_ NTSTATUS Status, _In_ PWCHAR Message) {
    KdNetErrorStatus = Status;
    KdNetErrorString = Message;

    return Status;
}

// Ticks from Since to Now, or 0 if the processors' counters disagree and Now is earlier.
static ULONG64 XenKdElapsed(_In_ ULONG64 Now, _In_ ULONG64 Since) {
    return Now > Since ? Now - Since : 0;
}

// A scalar OUT needs no guest interrupt or event-channel binding. Xen waits for the bridge to complete it when an
// ioreq server owns the port; with no server, the unclaimed write falls through to the device model.
static VOID XenKdAnnounce(_In_ PXENKD_ADAPTER Adapter, _In_ ULONG64 Now) {
    Adapter->LastAnnounceTime = Now;
    KeMemoryBarrier();
    WRITE_PORT_ULONG((PULONG)(ULONG_PTR)Adapter->IoPort, Adapter->HeaderPfn);
    Adapter->RendezvousAccepted = READ_PORT_ULONG((PULONG)(ULONG_PTR)Adapter->IoPort) == Adapter->HeaderPfn;
}

// Hexadecimal load option, parsed without CRT imports. A port change must be made on both ends.
static NTSTATUS XenKdConfigurePort(_In_opt_z_ PCSTR Options) {
    PCSTR Name = "XENKD_IOPORT=";
    PCSTR Word;
    PCSTR Value;
    ULONG Index;
    ULONG Port;
    ULONG Digits;
    ULONG Digit;
    CHAR Ch;

    XenKdIoPort = XENKD_DEFAULT_IO_PORT;
    while (Options != NULL && *Options != '\0') {
        if (*Options == ' ' || *Options == '\t' || *Options == '/') {
            Options++;
            continue;
        }
        Word = Options;
        while (*Options != '\0' && *Options != ' ' && *Options != '\t' && *Options != '/')
            Options++;
        for (Index = 0; Name[Index] != '\0' && Word + Index < Options; Index++) {
            Ch = Word[Index];
            if (Ch >= 'a' && Ch <= 'z')
                Ch -= 'a' - 'A';
            if (Ch != Name[Index])
                break;
        }
        if (Name[Index] != '\0')
            continue;

        Value = Word + Index;
        if (Options - Value >= 2 && Value[0] == '0' && (Value[1] == 'x' || Value[1] == 'X'))
            Value += 2;
        Port = Digits = 0;
        while (Value < Options) {
            Ch = *Value++;
            if (Ch >= '0' && Ch <= '9')
                Digit = Ch - '0';
            else if (Ch >= 'a' && Ch <= 'f')
                Digit = Ch - 'a' + 10;
            else if (Ch >= 'A' && Ch <= 'F')
                Digit = Ch - 'A' + 10;
            else
                goto invalid;
            if (++Digits > 4)
                goto invalid;
            Port = (Port << 4) | Digit;
        }
        if (Digits == 0 || Port == 0 || Port > 0xFFFC || (Port & 3) != 0)
            goto invalid;
        XenKdIoPort = (USHORT)Port;
    }
    return STATUS_SUCCESS;

invalid:
    return XenKdFail(STATUS_INVALID_PARAMETER, L"xenkd: XENKD_IOPORT must be an aligned nonzero hexadecimal I/O port");
}

// Housekeeping, done on every call from KDNET that may touch the rings: follow dom0's heartbeat, and announce the
// shared area while dom0 isn't attached. Returns whether it is, i.e. whether dom0's fields can be used.
static BOOLEAN XenKdCheckDom0(_In_ PXENKD_ADAPTER Adapter) {
    PXENKD_SHM_HEADER Header = &Adapter->Shm->Header;
    ULONG64 Now;
    ULONG Generation;
    ULONG Heartbeat;
    BOOLEAN Attached;

    Now = KdReadCycleCounter(NULL);

    KeMemoryBarrier();
    Generation = Header->Dom0Generation;
    Heartbeat = Header->Dom0Heartbeat;
    KeMemoryBarrier();

    // Only a change counts, so a long gap between our calls doesn't make dom0 look dead.
    if (Heartbeat != Adapter->LastHeartbeat) {
        Adapter->LastHeartbeat = Heartbeat;
        Adapter->LastHeartbeatTime = Now;
    }

    Attached = Adapter->RendezvousAccepted && Generation == Header->Generation &&
        XenKdElapsed(Now, Adapter->LastHeartbeatTime) < XENKD_DOM0_TIMEOUT_S * Adapter->TicksPerSecond;

    if (!Attached &&
        XenKdElapsed(Now, Adapter->LastAnnounceTime) >= XENKD_ANNOUNCE_INTERVAL_S * Adapter->TicksPerSecond)
        XenKdAnnounce(Adapter, Now);

    return Attached;
}

// Put a frame in the TX ring. Without dom0, the frame is dropped, as a NIC without a link would.
static NTSTATUS XenKdSendFrame(_In_ PXENKD_ADAPTER Adapter, _In_reads_bytes_(Length) PUCHAR Data, _In_ ULONG Length) {
    PXENKD_SHM Shm = Adapter->Shm;
    PXENKD_SHM_SLOT Slot;
    ULONG64 Start;
    ULONG prod;
    ULONG cons;

    if (!XenKdCheckDom0(Adapter))
        return STATUS_SUCCESS;

    prod = Shm->Header.TxProd;
    Start = KdReadCycleCounter(NULL);

    for (;;) {
        KeMemoryBarrier();
        cons = Shm->Header.TxCons;
        KeMemoryBarrier();

        if (prod - cons < XENKD_SHM_TX_SLOTS)
            break;

        // More than a ring's worth means dom0 is broken.
        if (prod - cons > XENKD_SHM_TX_SLOTS)
            return STATUS_IO_TIMEOUT;

        // Ring full: wait for dom0, unless it went away.
        if (Shm->Header.Dom0Generation != Shm->Header.Generation)
            return STATUS_SUCCESS;

        if (XenKdElapsed(KdReadCycleCounter(NULL), Start) >= XENKD_TX_TIMEOUT_MS * Adapter->TicksPerSecond / 1000)
            return STATUS_IO_TIMEOUT;

        KeStallExecutionProcessor(XENKD_TX_STALL_US);
    }

    Slot = &Shm->Tx[prod % XENKD_SHM_TX_SLOTS];
    Slot->Length = Length;
    RtlCopyMemory(Slot->Data, Data, Length);
    KeMemoryBarrier();
    Shm->Header.TxProd = prod + 1;

    return STATUS_SUCCESS;
}

static ULONG XenKdAllocateRxBuffer(_In_ PXENKD_ADAPTER Adapter) {
    ULONG Index;

    for (Index = 0; Index < XENKD_RX_BUFFERS; Index++) {
        if (!Adapter->Rx[Index].InUse) {
            Adapter->Rx[Index].InUse = TRUE;
            Adapter->Rx[Index].Length = 0;
            return Index;
        }
    }

    return XENKD_RX_NONE;
}

// Take the next frame from the RX ring. Returns the RX buffer it was copied to, or XENKD_RX_NONE.
static ULONG XenKdReceiveFrame(_In_ PXENKD_ADAPTER Adapter) {
    PXENKD_SHM Shm = Adapter->Shm;
    PXENKD_SHM_SLOT Slot;
    ULONG Length;
    ULONG Index;
    ULONG prod;
    ULONG cons;

    cons = Shm->Header.RxCons;
    KeMemoryBarrier();
    prod = Shm->Header.RxProd;
    KeMemoryBarrier();

    if (prod == cons)
        return XENKD_RX_NONE;

    // More than a ring's worth means dom0 is broken: drop whatever it claims to have.
    if (prod - cons > XENKD_SHM_RX_SLOTS) {
        Shm->Header.RxCons = prod;
        return XENKD_RX_NONE;
    }

    Slot = &Shm->Rx[cons % XENKD_SHM_RX_SLOTS];
    Length = Slot->Length;

    if (Length == 0 || Length > XENKD_MAX_FRAME) {
        KeMemoryBarrier();
        Shm->Header.RxCons = cons + 1;
        return XENKD_RX_NONE;
    }

    // If KDNET still holds all the buffers, leave the frame in the ring for the next call.
    Index = XenKdAllocateRxBuffer(Adapter);
    if (Index == XENKD_RX_NONE)
        return XENKD_RX_NONE;

    RtlCopyMemory(Adapter->Rx[Index].Data, Slot->Data, Length);
    Adapter->Rx[Index].Length = Length;
    KeMemoryBarrier();
    Shm->Header.RxCons = cons + 1;

    return Index;
}

// Fill the shared area's header, which dom0 can't attach to until Signature is set.
static NTSTATUS XenKdInitializeShm(_In_ PXENKD_ADAPTER Adapter) {
    PXENKD_SHM_HEADER Header = &Adapter->Shm->Header;
    PHYSICAL_ADDRESS Address;
    ULONG64 Now;
    ULONG Generation;
    ULONG Index;

    Now = KdReadCycleCounter(&Adapter->TicksPerSecond);
    // Without a frequency, assume a fast counter: the timeouts get longer, but stay bounded.
    if (Adapter->TicksPerSecond == 0)
        Adapter->TicksPerSecond = 1000000000;

    // A new generation tells dom0 that whatever it attached to before is gone.
    Generation = (ULONG)(Now ^ (Now >> 32));
    if (Generation == Header->Generation)
        Generation++;
    if (Generation == 0)
        Generation++;

    // Zero the whole header: Signature first, then the indices, dom0's fields and the reserved space.
    Header->Signature = 0;
    KeMemoryBarrier();
    RtlZeroMemory(Header, sizeof(*Header));

    Address = KdGetPhysicalAddress(Adapter->Shm);
    if (Address.QuadPart == 0 || ((ULONG64)Address.QuadPart >> PAGE_SHIFT) >= XENKD_IO_DETACH)
        return XenKdFail(STATUS_INVALID_ADDRESS, L"xenkd: invalid shared header PFN for the I/O rendezvous");
    Adapter->HeaderPfn = (ULONG)((ULONG64)Address.QuadPart >> PAGE_SHIFT);

    for (Index = 0; Index < XENKD_SHM_RING_PAGES; Index++) {
        Address = KdGetPhysicalAddress((PUCHAR)Adapter->Shm + (Index + 1) * PAGE_SIZE);
        if (Address.QuadPart == 0)
            return XenKdFail(STATUS_INVALID_ADDRESS, L"xenkd: cannot get the physical address of the shared area");

        Header->RingGfn[Index] = (ULONG64)Address.QuadPart >> PAGE_SHIFT;
    }

    Header->Generation = Generation;

    Adapter->LastHeartbeat = 0;
    Adapter->LastHeartbeatTime = Now;

    KeMemoryBarrier();
    Header->Signature = XENKD_SHM_SIGNATURE;

    return STATUS_SUCCESS;
}

NTSTATUS
XenKdInitializeController(__in PKDNET_SHARED_DATA KdNet) {
    PXENKD_ADAPTER Adapter;
    NTSTATUS Status;
    ULONG Index;

    Adapter = (PXENKD_ADAPTER)KdNet->Hardware;
    Adapter->KdNet = KdNet;
    Adapter->IoPort = XenKdIoPort;
    Adapter->Initialized = FALSE;
    Adapter->RendezvousAccepted = FALSE;
    Adapter->Shm = ALIGN_UP_POINTER_BY(Adapter->ShmSpace, PAGE_SIZE);

    // dom0 may still be attached to a previous controller in this memory: stop it writing as soon as possible.
    Adapter->Shm->Header.Signature = 0;
    KeMemoryBarrier();

    for (Index = 0; Index < XENKD_RX_BUFFERS; Index++) {
        Adapter->Rx[Index].Length = 0;
        Adapter->Rx[Index].InUse = FALSE;
    }

    for (Index = 0; Index < XENKD_TX_BUFFERS; Index++)
        Adapter->Tx[Index].InUse = FALSE;

    if (Adapter->KdNet->Device->VendorID != PCI_VENDOR_ID_XEN ||
        Adapter->KdNet->Device->DeviceID != PCI_DEVICE_ID_XENKD)
        return XenKdFail(STATUS_NO_SUCH_DEVICE, L"xenkd: not the xenkd PCI device");

    Status = XenKdInitializeShm(Adapter);
    if (!NT_SUCCESS(Status))
        return Status;
    Adapter->Initialized = TRUE;

    // The target MAC address is left alone: KDNET has already derived it from the SMBIOS UUID, which is also what the
    // dom0 bridge expects.
    KdNet->LinkSpeed = 1000;
    KdNet->LinkDuplex = 1;

    XenKdAnnounce(Adapter, KdReadCycleCounter(NULL));

    return STATUS_SUCCESS;
}

VOID XenKdShutdownController(__in PVOID Context) {
    PXENKD_ADAPTER Adapter = Context;

    if (!Adapter->Initialized)
        return;

    // The bridge unmaps before completing this OUT, so KDNET can reclaim the pages on return.
    Adapter->Shm->Header.Signature = 0;
    Adapter->Shm->Header.Generation = 0;
    KeMemoryBarrier();

    WRITE_PORT_ULONG((PULONG)(ULONG_PTR)Adapter->IoPort, XENKD_IO_DETACH);
    Adapter->Initialized = FALSE;
    Adapter->RendezvousAccepted = FALSE;
}

VOID XenKdSetHibernateRange(VOID) {
    PoSetHiberRange(NULL, PO_MEM_BOOT_PHASE, (PVOID)(ULONG_PTR)XenKdSetHibernateRange, 0, 'endK');
}

ULONG
XenKdGetHardwareContextSize(__in PDEBUG_DEVICE_DESCRIPTOR Device) {
    UNREFERENCED_PARAMETER(Device);

    return sizeof(XENKD_ADAPTER);
}

NTSTATUS
XenKdGetRxPacket(__in PVOID Context, __out PULONG Handle, __out PVOID *Packet, __out PULONG Length) {
    PXENKD_ADAPTER Adapter = Context;
    ULONG Index;

    if (!Adapter->Initialized)
        return STATUS_IO_TIMEOUT;

    // KDNET polls here even while the guest runs, which gives the housekeeping its chances. Never wait here.
    if (!XenKdCheckDom0(Adapter))
        return STATUS_IO_TIMEOUT;

    Index = XenKdReceiveFrame(Adapter);
    if (Index == XENKD_RX_NONE)
        return STATUS_IO_TIMEOUT;

    *Handle = Index;
    *Packet = Adapter->Rx[Index].Data;
    *Length = Adapter->Rx[Index].Length;

    return STATUS_SUCCESS;
}

VOID XenKdReleaseRxPacket(__in PVOID Context, ULONG Handle) {
    PXENKD_ADAPTER Adapter = Context;
    ULONG Index = Handle & ~HANDLE_FLAGS;

    if (Index >= XENKD_RX_BUFFERS)
        return;

    Adapter->Rx[Index].Length = 0;
    Adapter->Rx[Index].InUse = FALSE;
}

NTSTATUS
XenKdGetTxPacket(__in PVOID Context, __out PULONG Handle) {
    PXENKD_ADAPTER Adapter = Context;
    ULONG Index;

    for (Index = 0; Index < XENKD_TX_BUFFERS; Index++) {
        if (!Adapter->Tx[Index].InUse) {
            Adapter->Tx[Index].InUse = TRUE;
            *Handle = Index | TRANSMIT_HANDLE;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_IO_TIMEOUT;
}

NTSTATUS
XenKdSendTxPacket(__in PVOID Context, ULONG Handle, ULONG Length) {
    PXENKD_ADAPTER Adapter = Context;
    ULONG Index = Handle & ~HANDLE_FLAGS;
    NTSTATUS Status;

    if (!(Handle & TRANSMIT_HANDLE) || Index >= XENKD_TX_BUFFERS)
        return STATUS_INVALID_PARAMETER;

    // Always synchronous, even with TRANSMIT_ASYNC: once the frame is in the TX ring, it's on the wire and the buffer
    // can be reused.
    if (Length > XENKD_MAX_FRAME)
        Status = STATUS_INVALID_PARAMETER;
    else if (!Adapter->Initialized)
        Status = STATUS_UNSUCCESSFUL;
    else
        Status = XenKdSendFrame(Adapter, Adapter->Tx[Index].Data, Length);

    Adapter->Tx[Index].InUse = FALSE;

    return Status;
}

PVOID
XenKdGetPacketAddress(__in PVOID Context, ULONG Handle) {
    PXENKD_ADAPTER Adapter = Context;
    ULONG Index = Handle & ~HANDLE_FLAGS;

    if (Handle & TRANSMIT_HANDLE)
        return Index < XENKD_TX_BUFFERS ? Adapter->Tx[Index].Data : NULL;

    return Index < XENKD_RX_BUFFERS ? Adapter->Rx[Index].Data : NULL;
}

ULONG
XenKdGetPacketLength(__in PVOID Context, ULONG Handle) {
    PXENKD_ADAPTER Adapter = Context;
    ULONG Index = Handle & ~HANDLE_FLAGS;

    if (Handle & TRANSMIT_HANDLE)
        return Index < XENKD_TX_BUFFERS ? XENKD_MAX_FRAME : 0;

    return Index < XENKD_RX_BUFFERS ? Adapter->Rx[Index].Length : 0;
}

NTSTATUS
XenKdDeviceControl(
    __in PVOID Context,
    __in ULONG RequestCode,
    __in_bcount(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount(OutputBufferSize) PVOID OutputBuffer,
    __in ULONG OutputBufferSize) {
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(RequestCode);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    // The serial flow control requests aren't used in the packet model, and there's nothing else to control.
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
KdInitializeLibrary(
    __in PKDNET_EXTENSIBILITY_IMPORTS ImportTable,
    __in_opt PCHAR LoaderOptions,
    __inout PDEBUG_DEVICE_DESCRIPTOR Device) {
    NTSTATUS Status;
    PKDNET_EXTENSIBILITY_EXPORTS Exports;

    __security_init_cookie();

    KdNetExtensibilityImports = ImportTable;
    if ((KdNetExtensibilityImports == NULL) || (KdNetExtensibilityImports->FunctionCount != KDNET_EXT_IMPORTS)) {
        Status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    Exports = KdNetExtensibilityImports->Exports;
    if ((Exports == NULL) || (Exports->FunctionCount != KDNET_EXT_EXPORTS)) {
        Status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    Status = XenKdConfigurePort(LoaderOptions);
    if (!NT_SUCCESS(Status))
        goto out;

    // Packet-based extensibility model: KDNET hands us whole Ethernet frames, which go through rings in memory shared
    // with dom0. KdReadSerialByte and KdWriteSerialByte must stay NULL (KDNET zeroes the table), or KDNET rejects the
    // module.
    Exports->KdInitializeController = XenKdInitializeController;
    Exports->KdShutdownController = XenKdShutdownController;
    Exports->KdSetHibernateRange = XenKdSetHibernateRange;
    Exports->KdGetHardwareContextSize = XenKdGetHardwareContextSize;
    Exports->KdGetRxPacket = XenKdGetRxPacket;
    Exports->KdReleaseRxPacket = XenKdReleaseRxPacket;
    Exports->KdGetTxPacket = XenKdGetTxPacket;
    Exports->KdSendTxPacket = XenKdSendTxPacket;
    Exports->KdGetPacketAddress = XenKdGetPacketAddress;
    Exports->KdGetPacketLength = XenKdGetPacketLength;
    Exports->KdDeviceControl = XenKdDeviceControl;

    Device->Memory.Length = XenKdGetHardwareContextSize(Device);

    return STATUS_SUCCESS;

out:
    return Status;
}
