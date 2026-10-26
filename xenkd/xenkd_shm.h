#pragma once

// The protocol between xenkd and the dom0 bridge (scripts/xenkd-bridge.py, whose SHM_* constants and SharedRings
// class mirror this file: change both together).
//
// Overview
// --------
// xenkd carries KDNET's Ethernet frames through an area of guest memory that dom0 maps directly with
// xenforeignmemory_map. The area is page-aligned inside the memory KDNET reserves for the module (KdNet->Hardware),
// and made of XENKD_SHM_PAGES pages:
//
//   page 0             the header (XENKD_SHM_HEADER)
//   pages 1-16         the TX ring: XENKD_SHM_TX_SLOTS slots, guest to dom0
//   pages 17-24        the RX ring: XENKD_SHM_RX_SLOTS slots, dom0 to guest
//
// The pages aren't physically contiguous: Gfn[] lists the guest frame of each one, and dom0 maps them in that order to
// see the area as one block. No grant tables, xenstore or event channels are involved (those belong to xenbus.sys),
// and both sides poll.
//
// All fields are little-endian 32-bit values (64-bit for Gfn[]), naturally aligned, so x86 loads and stores of them
// are atomic. Every field has exactly one writer, listed below. Each side treats what the other wrote as untrusted.
//
// Rendezvous
// ----------
// dom0 learns where the header is from a line that xenkd writes to the PV console ring:
//
//   \nxenkd-shm v1 gfn=<Gfn[0], lowercase hex> gen=<Generation, lowercase hex>\n
//
// xenkd writes it at KdInitializeController, then once a second (XENKD_ANNOUNCE_INTERVAL_S) for as long as dom0 isn't
// attached. The line goes into the ring whole or not at all, and xenkd never waits for room: another one follows. A
// line with the same generation as dom0's current attachment is ignored by dom0, since xenkd may announce once more
// before it sees dom0's heartbeat.
//
// Guest initialization (KdInitializeController)
// ---------------------------------------------
//   1. Magic = 0, barrier, then zero the whole header page (indices, dom0's fields and reserved space included).
//   2. Fill Version, PageCount, SlotSize, TxSlots, RxSlots and Gfn[] (from KdGetPhysicalAddress of each page).
//   3. Generation = a new nonzero value (from the cycle counter), different from the previous one.
//   4. Barrier, then Magic = XENKD_SHM_MAGIC: the area is now valid.
//   5. Announce.
//
// At KdShutdownController, xenkd sets Magic and Generation to 0. A new KdInitializeController starts over with a new
// generation, so a dom0 still attached to the old one notices and lets go.
//
// dom0 attachment
// ---------------
//   1. Map Gfn[0] alone, and check the header: Magic, Version, Generation equal to the announced one, a power-of-two
//      SlotSize between 4 + XENKD_MAX_FRAME and PAGE_SIZE, power-of-two slot counts, and a PageCount of at most
//      XENKD_SHM_MAX_PAGES that holds the header and both rings.
//   2. Map Gfn[0..PageCount), check that the first one is the announced frame, and check the header again there.
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
// Before every batch of writes, it checks that Magic and Generation are still the ones it attached to, which keeps the
// window in which it could write into pages Windows has reused as small as possible. A TX Length over
// XENKD_MAX_FRAME, or an index more than a ring away from dom0's, means the guest is broken: dom0 detaches.
//
// Detaching
// ---------
// dom0 detaches when Magic or Generation changes, when the guest breaks the rules above, when the domain goes away,
// and when the bridge exits. If the area is still the one it attached to, it first sets Dom0Generation = 0, so the
// guest stops using it at once and starts announcing again. Otherwise the guest notices from the heartbeat timeout.
//
// Compatibility
// -------------
// Any incompatible change bumps XENKD_SHM_VERSION, together with the "v1" of the announce line, which dom0 matches.
// Reserved fields are zero. The space after Dom0Heartbeat is kept for a guest-to-dom0 event channel, so that dom0 can
// wait instead of polling.

#define XENKD_SHM_MAGIC 0x53444B58 // "XKDS" in memory.
#define XENKD_SHM_VERSION 1

#define XENKD_SHM_MAX_PAGES 64
#define XENKD_SHM_SLOT_SIZE 2048
#define XENKD_SHM_TX_SLOTS 32 // Guest to dom0.
#define XENKD_SHM_RX_SLOTS 16 // dom0 to guest. Few on purpose: a deep queue only fills up with stale retransmissions.

typedef struct _XENKD_SHM_HEADER {
    // Written by the guest. Magic is 0 while the area is (re)initialized or shut down, and Generation changes at every
    // KdInitializeController.
    ULONG Magic;
    ULONG Version;
    ULONG Generation;
    ULONG PageCount;
    ULONG SlotSize;
    ULONG TxSlots;
    ULONG RxSlots;
    ULONG Reserved0;
    ULONG64 Gfn[XENKD_SHM_MAX_PAGES]; // Guest frame of each page of the area, the header's first.
    UCHAR Reserved1[0x400 - 0x220];

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
    UCHAR Reserved6[PAGE_SIZE - 0x508];
} XENKD_SHM_HEADER, *PXENKD_SHM_HEADER;

C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Magic) == 0x000);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Version) == 0x004);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Generation) == 0x008);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, PageCount) == 0x00C);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, SlotSize) == 0x010);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, TxSlots) == 0x014);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, RxSlots) == 0x018);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Gfn) == 0x020);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, TxProd) == 0x400);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, TxCons) == 0x440);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, RxProd) == 0x480);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, RxCons) == 0x4C0);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Dom0Generation) == 0x500);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Dom0Heartbeat) == 0x504);
C_ASSERT(FIELD_OFFSET(XENKD_SHM_HEADER, Reserved6) == 0x508);
C_ASSERT(sizeof(XENKD_SHM_HEADER) == PAGE_SIZE);

typedef struct _XENKD_SHM_SLOT {
    // Read once and checked by the consumer: the other side may be broken.
    volatile ULONG Length;
    UCHAR Data[XENKD_SHM_SLOT_SIZE - sizeof(ULONG)];
} XENKD_SHM_SLOT, *PXENKD_SHM_SLOT;

C_ASSERT(sizeof(XENKD_SHM_SLOT) == XENKD_SHM_SLOT_SIZE);

typedef struct _XENKD_SHM {
    XENKD_SHM_HEADER Header;               // Page 0.
    XENKD_SHM_SLOT Tx[XENKD_SHM_TX_SLOTS]; // Pages 1-16.
    XENKD_SHM_SLOT Rx[XENKD_SHM_RX_SLOTS]; // Pages 17-24.
} XENKD_SHM, *PXENKD_SHM;

#define XENKD_SHM_PAGES (sizeof(XENKD_SHM) / PAGE_SIZE)

C_ASSERT(FIELD_OFFSET(XENKD_SHM, Tx) == 1 * PAGE_SIZE);
C_ASSERT(FIELD_OFFSET(XENKD_SHM, Rx) == 17 * PAGE_SIZE);
C_ASSERT(sizeof(XENKD_SHM) == 25 * PAGE_SIZE);
C_ASSERT(XENKD_SHM_PAGES <= XENKD_SHM_MAX_PAGES);
C_ASSERT((XENKD_SHM_TX_SLOTS & (XENKD_SHM_TX_SLOTS - 1)) == 0);
C_ASSERT((XENKD_SHM_RX_SLOTS & (XENKD_SHM_RX_SLOTS - 1)) == 0);
