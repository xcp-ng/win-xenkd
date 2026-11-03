#pragma once

// The protocol between xenkd and the dom0 bridge (scripts/xenkd-bridge.py, whose SHM_CDEF and SharedRings
// class mirror this file: change both together).
//
// Overview
// --------
// xenkd carries KDNET's Ethernet frames through an area of guest memory that dom0 maps directly with
// xenforeignmemory_map. The area is page-aligned inside the memory KDNET reserves for the module (KdNet->Hardware),
// and consists of one header page followed by XENKD_SHM_RING_PAGES ring pages:
//
//   page 0             the header (XENKD_SHM_HEADER)
//   pages 1-16         the TX ring: XENKD_SHM_TX_SLOTS slots, guest to dom0
//   pages 17-24        the RX ring: XENKD_SHM_RX_SLOTS slots, dom0 to guest
//
// The pages aren't physically contiguous. dom0 maps the header independently; RingGfn[] lists just the 24 ring pages,
// which dom0 maps together in that order. The guest uses no grant tables, xenstore or event-channel bindings (those
// belong to xenbus.sys), and both sides poll. dom0 binds Xen's own ioreq event channels for rendezvous only.
//
// All fields are little-endian 32-bit values (64-bit for RingGfn[]), naturally aligned, so x86 loads and stores of them
// are atomic. Every field has exactly one writer, listed below. Each side treats what the other wrote as untrusted.
//
// Rendezvous
// ----------
// xenkd writes the header PFN as a scalar 32-bit value to XENKD_DEFAULT_IO_PORT (0xEC), overridden by the hexadecimal
// XENKD_IOPORT load option. The bridge registers the same four-byte range with a secondary Xen ioreq server.
// The port identifies rendezvous v1. An incompatible rendezvous protocol uses a different port, configured on both
// ends. Ring layout compatibility is checked independently with Signature below.
//
// xenkd announces at KdInitializeController, then once a second (XENKD_ANNOUNCE_INTERVAL_S) while dom0 is detached.
// dom0 maps the header, reads its nonzero Generation, then validates and maps the area as described below. A repeated
// PFN with the same generation leaves an existing attachment alone. The header PFN must be below 0xFFFFFFFF; PFNs of
// the other pages remain 64-bit. All ones is reserved for shutdown: dom0 unmaps before completing that write.
// A scalar 32-bit read returns the accepted header PFN, or all ones while detached. xenkd reads back after each
// announcement and uses the link only after acknowledgement and a matching live heartbeat. No acknowledgement is
// needed to finish initialization: without a bridge, xenkd starts detached and retries on subsequent KDNET calls.
//
// I/O is synchronous when a server owns the port: guest interrupts need not be enabled, but a hung bridge can stall
// the issuing vCPU. With no server, writes fall through to the device model. The port must have no other handler.
//
// Guest initialization (KdInitializeController)
// ---------------------------------------------
//   1. Signature = 0, barrier, then zero the whole header page (indices, dom0's fields and reserved space included).
//   2. Fill RingGfn[] from KdGetPhysicalAddress of each ring page; cache the header PFN in the adapter.
//   3. Generation = a new nonzero value (from the cycle counter), different from the previous one.
//   4. Barrier, then Signature = XENKD_SHM_SIGNATURE: the area is now valid.
//   5. Announce.
//
// At KdShutdownController, xenkd sets Signature and Generation to 0 and writes all ones to the port. A new
// initialization starts over with a new generation, so a dom0 still attached to the old one notices and lets go.
//
// dom0 attachment
// ---------------
//   1. Map the header PFN, check Signature and its nonzero Generation, then read the fixed-length RingGfn[] array.
//      Reject duplicate PFNs and any ring PFN equal to the header PFN.
//   2. Map the ring pages separately, then recheck Signature, Generation and RingGfn[] through the retained header
//      mapping before writing anything. The geometry is fixed by this signature, not supplied by the guest.
//   3. TxCons = TxProd and RxProd = RxCons, dropping anything stale, then bump Dom0Heartbeat.
//   4. Dom0Generation = Generation: dom0 is attached. Since every dom0 field was rewritten first, a stale write from
//      an earlier attachment can't confuse the guest.
//
// Liveness
// --------
// dom0 increments Dom0Heartbeat on every poll. The guest considers dom0 attached, and only then uses dom0's fields,
// while Dom0Generation == Generation and Dom0Heartbeat has changed within the last XENKD_DOM0_TIMEOUT_S (2 s). Only a
// change counts: a long gap between KDNET's calls into xenkd doesn't make dom0 look dead.
//
// While dom0 isn't attached, the guest drops the frames KDNET sends (as a NIC without a link would), leaves the RX
// ring alone, and announces itself.
//
// Rings
// -----
// Prod and Cons are free-running ULONG indices: the slot of index i is i % count, and Prod - Cons (modulo 2^32) is the
// number of frames waiting, between 0 and count. Each slot holds a ULONG Length, then Length bytes of frame, at most
// XENKD_MAX_FRAME (1514).
//
//   Producer: write the slot (data and Length), barrier, then Prod + 1.
//   Consumer: read Prod, barrier, read the slot, then Cons + 1.
//
// TX: when the ring is full, the guest polls TxCons for up to XENKD_TX_TIMEOUT_MS (100 ms), then drops the frame. dom0
// drains the whole ring on every poll, and skips frames of length 0.
//
// RX: the guest takes one frame per KdGetRxPacket, copying it out of the ring. If KDNET holds all of xenkd's RX
// buffers, the frame stays in the ring until the next call. dom0 drops frames for the guest while the ring is full,
// rather than queuing them: they'd only be stale retransmissions by the time the guest got to them.
//
// Validation
// ----------
// The guest skips an RX slot whose Length is 0 or more than XENKD_MAX_FRAME, and resyncs (RxCons = RxProd) if RxProd
// is more than a ring ahead. If TxCons is more than a ring behind, it fails the send.
//
// dom0 keeps its own indices (TxCons, RxProd) locally and only ever writes them out, so the guest can't change them.
// Before every batch of writes, it checks that Signature and Generation are still the ones it attached to, which keeps
// the window in which it could write into pages Windows has reused as small as possible. A TX Length over
// XENKD_MAX_FRAME, or an index more than a ring away from dom0's, means the guest is broken: dom0 detaches.
//
// Detaching
// ---------
// dom0 detaches when Signature or Generation changes, when the guest breaks the rules above, when the domain goes away,
// and when the bridge exits. If the area is still the one it attached to, it first sets Dom0Generation = 0, so the
// guest stops using it at once and starts announcing again. Otherwise the guest notices from the heartbeat timeout.
//
// Compatibility
// -------------
// An incompatible ring layout uses a new XENKD_SHM_SIGNATURE on both ends. The complete value identifies the protocol;
// it is not split into magic and version fields. Zero means invalid. The I/O rendezvous stays independent.
// Reserved fields are zero. The space after Dom0Heartbeat is kept for a guest-to-dom0 event channel, so that dom0 can
// wait instead of polling.

// Copy the scissored section verbatim into SHM_CDEF in scripts/xenkd-bridge.py.
// ----8<----
#define XENKD_SHM_SIGNATURE 0x02444B58 // Shared-memory protocol identifier; zero is invalid.
#define XENKD_SHM_SLOT_SIZE 2048
#define XENKD_SHM_TX_SLOTS 32 // Guest to dom0.
#define XENKD_SHM_RX_SLOTS 16 // dom0 to guest. Few on purpose: a deep queue only fills up with stale retransmissions.
#define XENKD_SHM_RING_PAGES 24

// Literal array bounds keep these declarations usable by CFFI 1.9.1. The assertions below check the wire geometry.
typedef struct _XENKD_SHM_HEADER {
    // Written by the guest. Signature is 0 while the area is (re)initialized or shut down; Generation changes at every
    // KdInitializeController.
    ULONG Signature;
    ULONG Generation;
    ULONG64 RingGfn[XENKD_SHM_RING_PAGES]; // TX pages, then RX pages. Does not include the header.
    UCHAR Reserved1[0x338];                // 0x400 - 0xC8.

    // Each index in its own cache line.
    ULONG TxProd; // Guest.
    UCHAR Reserved2[60];
    volatile ULONG TxCons; // dom0.
    UCHAR Reserved3[60];
    volatile ULONG RxProd; // dom0.
    UCHAR Reserved4[60];
    ULONG RxCons; // Guest.
    UCHAR Reserved5[60];

    // Written by dom0. The guest uses dom0's fields only while Dom0Generation is Generation and Dom0Heartbeat changes.
    volatile ULONG Dom0Generation; // 0 when detached.
    volatile ULONG Dom0Heartbeat;  // Incremented on every dom0 poll.

    // Zero, for a dom0 event channel later on.
    UCHAR Reserved6[0xAF8]; // PAGE_SIZE - 0x508.
} XENKD_SHM_HEADER, *PXENKD_SHM_HEADER;

typedef struct _XENKD_SHM_SLOT {
    // Read once and checked by the consumer: the other side may be broken.
    volatile ULONG Length;
    UCHAR Data[2044]; // XENKD_SHM_SLOT_SIZE - sizeof(ULONG).
} XENKD_SHM_SLOT, *PXENKD_SHM_SLOT;

typedef struct _XENKD_SHM {
    XENKD_SHM_HEADER Header;               // Page 0.
    XENKD_SHM_SLOT Tx[XENKD_SHM_TX_SLOTS]; // Pages 1-16.
    XENKD_SHM_SLOT Rx[XENKD_SHM_RX_SLOTS]; // Pages 17-24.
} XENKD_SHM, *PXENKD_SHM;
// ---->8----

// Detailed field offsets are checked against the CFFI layout by test_xenkd_bridge.py.
C_ASSERT(sizeof(XENKD_SHM_HEADER) == PAGE_SIZE);
C_ASSERT(sizeof(XENKD_SHM_SLOT) == XENKD_SHM_SLOT_SIZE);

// Both rings must be contiguous and fill the mapped pages exactly, with no partial page or trailing padding.
C_ASSERT(RTL_FIELD_SIZE(XENKD_SHM, Tx) + RTL_FIELD_SIZE(XENKD_SHM, Rx) == XENKD_SHM_RING_PAGES * PAGE_SIZE);
C_ASSERT(sizeof(XENKD_SHM) == (1 + XENKD_SHM_RING_PAGES) * PAGE_SIZE);

// Slot counts must divide the 32-bit counter range so modulo indexing remains continuous across wraparound.
C_ASSERT(XENKD_SHM_TX_SLOTS > 0 && (XENKD_SHM_TX_SLOTS & (XENKD_SHM_TX_SLOTS - 1)) == 0);
C_ASSERT(XENKD_SHM_RX_SLOTS > 0 && (XENKD_SHM_RX_SLOTS & (XENKD_SHM_RX_SLOTS - 1)) == 0);
