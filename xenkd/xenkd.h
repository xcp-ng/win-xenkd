#pragma once

#include <ntddk.h>
#include <stdint.h>
#include <kdnetshareddata.h>
#include <kdnetextensibility.h>

#if defined(_M_X64)
#ifndef __x86_64__
#define __x86_64__
#endif
#else
#error "xenkd only supports x64 HVM guests"
#endif

#pragma warning(push)
#pragma warning(disable : 4200 4214)

#define __XEN_INTERFACE_VERSION__ 0x00040800
#include <xen/public/xen.h>
#include <xen/public/errno.h>
#include <xen/public/event_channel.h>
#include <xen/public/hvm/hvm_op.h>
#include <xen/public/hvm/params.h>
#include <xen/public/io/console.h>

#pragma warning(pop)

#include "xenkd_shm.h"

#define PCI_VENDOR_ID_XEN 0x5853
#define PCI_DEVICE_ID_XENKD 0xC201

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
    // The PV console, now only used to announce the shared area to dom0.
    struct xencons_interface *Ring;
    // Set when the backend needs to be kicked, i.e. after we produced output.
    BOOLEAN NotifyPending;

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
