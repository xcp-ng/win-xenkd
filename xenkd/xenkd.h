#pragma once

#include <ntddk.h>
#include <kdnetshareddata.h>
#include <kdnetextensibility.h>

#if !defined(_M_X64)
#error "xenkd only supports x64 HVM guests"
#endif

#include "xenkd_shm.h"

#define PCI_VENDOR_ID_XEN 0x5853
#define PCI_DEVICE_ID_XENKD 0xC201

// Rendezvous v1: write a 32-bit PFN (all ones detaches), read the accepted PFN (all ones if detached).
// Keep in sync with DEFAULT_IO_PORT in the bridge.
#define XENKD_DEFAULT_IO_PORT 0xEC
#define XENKD_IO_DETACH MAXULONG

// Largest Ethernet frame (without FCS) that KDNET may send or that we accept.
#define XENKD_MAX_FRAME 1514
#define XENKD_BUFFER_SIZE 2048

#define XENKD_RX_BUFFERS 4
#define XENKD_TX_BUFFERS 2
#define XENKD_RX_NONE ((ULONG) - 1)

C_ASSERT(XENKD_MAX_FRAME <= RTL_FIELD_SIZE(XENKD_SHM_SLOT, Data));

typedef struct _XENKD_RX_BUFFER {
    UCHAR Data[XENKD_BUFFER_SIZE];
    ULONG Length;
    // Held by KDNET.
    BOOLEAN InUse;
} XENKD_RX_BUFFER, *PXENKD_RX_BUFFER;

typedef struct _XENKD_TX_BUFFER {
    UCHAR Data[XENKD_BUFFER_SIZE];
    BOOLEAN InUse;
} XENKD_TX_BUFFER, *PXENKD_TX_BUFFER;

typedef struct _XENKD_ADAPTER {
    PKDNET_SHARED_DATA KdNet;
    USHORT IoPort;
    BOOLEAN Initialized;
    BOOLEAN RendezvousAccepted;
    ULONG HeaderPfn;

    // The shared area, page-aligned inside ShmSpace.
    PXENKD_SHM Shm;

    // Tracking dom0, in KdReadCycleCounter ticks.
    ULONG64 TicksPerSecond;
    ULONG LastHeartbeat;       // Dom0Heartbeat as last seen.
    ULONG64 LastHeartbeatTime; // When it last changed.
    ULONG64 LastAnnounceTime;

    XENKD_RX_BUFFER Rx[XENKD_RX_BUFFERS];
    XENKD_TX_BUFFER Tx[XENKD_TX_BUFFERS];

    UCHAR ShmSpace[sizeof(XENKD_SHM) + PAGE_SIZE];
} XENKD_ADAPTER, *PXENKD_ADAPTER;
