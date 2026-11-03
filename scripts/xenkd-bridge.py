#!/usr/bin/env python3
"""Bridge a guest's xenkd to the debugger, over UDP from dom0.

xenkd gives KDNET a network card made of two rings of Ethernet frames in guest memory (see xenkd/xenkd_shm.h), and
announces their header PFN with a 32-bit I/O write. The bridge maps the rings from dom0, polls them, and stands in for
KDNET's network: it answers the guest's ARP, forwards its UDP payloads to the debugger from an ordinary UDP socket, and
wraps the debugger's replies back into frames. The debugger only needs to reach dom0 on one UDP port: the guest's
HOST_IP:port, or --debugger. DHCP isn't answered, so the guest needs NO_DHCP and TARGET_IP (as Enable-XenKd.ps1 sets
them). Attach with `windbg -k net:port=<port>,key=<key>`.

The bridge can be restarted during a debug session: it talks to the debugger from a fixed port, knows the guest's
address right away (its MAC follows from the domain's UUID, its IP is --guest-ip if given), and xenkd announces its
rings again within about 3 s of the bridge going away.

It follows the guest across reboots, which change its domid: by its UUID on XAPI hosts (XenServer, XCP-ng), where names
can repeat, and by its name with xl, where `xl create` gives a new UUID unless the config sets one. A domid, or the
other of the two, is looked up from the running domain at startup.

Run in dom0 as root. Needs xenstore-read, xenstore-list, libxenforeignmemory, libxendevicemodel and libxenevtchn.
The I/O port defaults to 0xec; --io-port and the guest's XENKD_IOPORT load option must agree. Its four bytes must be
reserved in guest ACPI and unused by other virtual hardware. The PV console is left alone.
"""

import argparse
import ctypes
import errno
import hashlib
import hmac
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

# The largest Ethernet frame (without FCS) that xenkd sends or accepts (XENKD_MAX_FRAME).
MAX_FRAME = 1514
# How often to check whether the domain was rebooted or destroyed.
DOMAIN_CHECK_INTERVAL = 2.0
# A UUID, as given on the command line or found in xenstore.
UUID_FORMAT = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
# Only XAPI hosts (XenServer, XCP-ng) have it.
XAPI_INVENTORY = "/etc/xensource-inventory"
# While attached, how often to poll the rings: every ACTIVE_POLL_INTERVAL (continuously with --fast) for ACTIVE_PERIOD
# after the last frame in either direction, then slower.
ACTIVE_POLL_INTERVAL = 0.0002
IDLE_POLL_INTERVAL = 0.005
ACTIVE_PERIOD = 1.0
# With --fast, how often to check I/O notifications and timeouts again while spinning.
SPIN_SLICE = 0.001

# The shared area, as laid out in xenkd/xenkd_shm.h: a header page, then the TX ring (guest to dom0) and the RX ring
# (dom0 to guest). Each slot is a 32-bit length followed by the frame. Indices are free-running 32-bit counters.
PAGE_SIZE = 4096
SHM_VERSION = 2
SHM_SIGNATURE = 0x00444B58 | (SHM_VERSION << 24)  # "XKD", then version
SHM_SIGNATURE_OFFSET = 0x000
SHM_GENERATION_OFFSET = 0x004
SHM_GFN_OFFSET = 0x008
SHM_SLOT_SIZE = 2048
SHM_TX_SLOTS = 32
SHM_RX_SLOTS = 16
SHM_RING_PAGES = (SHM_TX_SLOTS + SHM_RX_SLOTS) * SHM_SLOT_SIZE // PAGE_SIZE
SHM_RX_OFFSET = SHM_TX_SLOTS * SHM_SLOT_SIZE
SHM_TX_PROD = 0x400
SHM_TX_CONS = 0x440
SHM_RX_PROD = 0x480
SHM_RX_CONS = 0x4C0
SHM_DOM0_GENERATION = 0x500
SHM_DOM0_HEARTBEAT = 0x504
INDEX_MASK = 0xFFFFFFFF
# Rendezvous v1 (XENKD_DEFAULT_IO_PORT / XENKD_IO_DETACH). A port change is an explicit choice on both ends.
DEFAULT_IO_PORT = 0xEC
IO_DETACH = 0xFFFFFFFF
# Xen public hvm/ioreq.h: one 32-byte request per vCPU, in one shared page.
IOREQ = struct.Struct("<QQIIIHBB")
IOREQ_STATE_OFFSET = 30
IOREQ_READY = 1
IOREQ_INPROCESS = 2
IORESP_READY = 3
IOREQ_READ = 0x20
IOREQ_DATA_IS_PTR = 0x10
IOREQ_TYPE_PIO = 0
# Give Xen time to consume responses before freeing the server and its event channels.
IOREQ_DRAIN_TIMEOUT = 1.0

ETHERTYPE_IPV4 = b"\x08\x00"
ETHERTYPE_ARP = b"\x08\x06"
IPPROTO_UDP = 17
DHCP_SERVER_PORT = 67
ARP_REQUEST = 1
ARP_REPLY = 2
# What the guest sees as the MAC of every other host (locally administered).
PROXY_MAC = b"\x02\x00\x00\x6b\x64\x00"
# Where Enable-XenKd.ps1 points KDNET (-HostIp and -Port) unless told otherwise.
DEFAULT_DESTINATION = "169.254.0.1:5364"


def log(message):
    print(message, file=sys.stderr, flush=True)


def format_mac(mac):
    return ":".join("%02x" % b for b in mac)


def describe_frame(frame):
    """One line about a frame, for --verbose."""
    ethertype = frame[12:14]
    if ethertype == ETHERTYPE_ARP and len(frame) >= 42:
        source, destination = map(socket.inet_ntoa, (frame[28:32], frame[38:42]))
        what = "ARP %s > %s" % (source, destination)
    elif ethertype == ETHERTYPE_IPV4 and len(frame) >= 34:
        source, destination = map(socket.inet_ntoa, (frame[26:30], frame[30:34]))
        what = "IPv4 proto %d %s > %s" % (frame[23], source, destination)
    else:
        what = "ethertype %s" % ethertype.hex()
    return "%s, %d bytes" % (what, len(frame))


def query(*command):
    """Run a command, and return its output, or None if it fails or prints nothing."""
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        universal_newlines=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def read_domain(domid, key):
    """A domain's UUID (key "vm", which holds /vm/<uuid>) or name (key "name"), or None."""
    value = query("xenstore-read", "/local/domain/%s/%s" % (domid, key))
    if value and key == "vm":
        return value.rsplit("/", 1)[-1].lower()
    return value


def find_domains(key, value):
    """The domids of the running domains, other than dom0, whose UUID or name (key) is value."""
    domids = (query("xenstore-list", "/local/domain") or "").split()
    return [d for d in domids if d != "0" and read_domain(d, key) == value]


def follow_key():
    """What identifies a domain across reboots: its UUID with XAPI, its name with xl (see the module's docstring)."""
    return "vm" if os.path.exists(XAPI_INVENTORY) else "name"


def resolve_domain(domain, key):
    """The UUID or name (key) to follow the domain by, given its UUID, domid or name."""
    if UUID_FORMAT.match(domain):
        given, domain = "vm", domain.lower()
    else:
        given = None if domain.isdigit() else "name"
    if given == key:
        return domain
    domids = find_domains(given, domain) if given else [domain]
    if len(domids) > 1:
        raise SystemExit(
            "domains %s are all named %s: give the UUID of one"
            % (", ".join(domids), domain)
        )
    value = read_domain(domids[0], key) if domids else None
    what = "UUID" if key == "vm" else "name"
    if value is None:
        raise SystemExit(
            "no running domain %s (give its %s to wait for it to start)"
            % (domain, what)
        )
    log("following domain %s by its %s %s" % (domain, what, value))
    return value


def kdnet_mac(smbios_uuid):
    """The MAC KDNET gives itself: an HMAC of the SMBIOS UUID (the domain's), locally administered."""
    digest = hmac.new(b"MAC_KEY\0", uuid.UUID(smbios_uuid).bytes, hashlib.sha256)
    mac = bytearray(digest.digest()[:6])
    mac[0] = (mac[0] & 0xFE) | 0x02
    return bytes(mac)


class Domain:
    """Follow a guest's identity without acquiring its console."""

    def __init__(self, key, value):
        """Follow the domain whose UUID (key "vm") or name (key "name") is value."""
        self.key, self.value = key, value
        self.domid = self.status = None
        self.next_check = 0.0

    def set_status(self, status):
        # Log state changes only, not every check.
        if status != self.status:
            self.status = status
            log(status)

    def poll(self):
        """Return True when the domain changes, including disappearance."""
        now = time.monotonic()
        if now < self.next_check:
            return False
        self.next_check = now + DOMAIN_CHECK_INTERVAL

        if self.domid is not None and read_domain(self.domid, self.key) == self.value:
            return False
        old = self.domid
        domids = find_domains(self.key, self.value)
        if not domids:
            self.domid = None
            self.set_status("waiting for domain %s..." % self.value)
        else:
            if len(domids) != 1:
                raise SystemExit("multiple domains match %s: %s" % (self.value, domids))
            self.domid = domids[0]
            self.set_status("following domain %s" % self.domid)
        return old != self.domid

    def time_to_poll(self):
        """How long until poll() has something to check."""
        return max(0.0, self.next_check - time.monotonic())


class ForeignMemory:
    """Guest pages mapped into dom0, through libxenforeignmemory."""

    PROT_READ_WRITE = 3
    PyBUF_WRITE = 0x200

    def __init__(self):
        lib = ctypes.CDLL("libxenforeignmemory.so.1", use_errno=True)
        handle = ctypes.c_void_p
        lib.xenforeignmemory_open.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        lib.xenforeignmemory_open.restype = handle
        lib.xenforeignmemory_map.argtypes = [
            handle,
            ctypes.c_uint32,  # domid
            ctypes.c_int,  # prot
            ctypes.c_size_t,  # pages
            ctypes.POINTER(ctypes.c_ulong),  # xen_pfn_t arr[]
            ctypes.POINTER(ctypes.c_int),  # err[]
        ]
        lib.xenforeignmemory_map.restype = ctypes.c_void_p
        lib.xenforeignmemory_unmap.argtypes = [handle, ctypes.c_void_p, ctypes.c_size_t]
        lib.xenforeignmemory_close.argtypes = [handle]
        self.lib = lib
        self.handle = lib.xenforeignmemory_open(None, 0)
        if not self.handle:
            error = ctypes.get_errno()
            raise OSError(error, "xenforeignmemory_open: %s" % os.strerror(error))

        # A memoryview straight over the mapping, which ctypes arrays can't give (their format is "<B").
        self.memory_view = ctypes.pythonapi.PyMemoryView_FromMemory
        self.memory_view.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int]
        self.memory_view.restype = ctypes.py_object

    def map(self, domid, gfns):
        """Map the guest frames gfns (in this order), writable, and return (address, memoryview). The view is invalid
        once unmap() is called with the address."""
        count = len(gfns)
        errors = (ctypes.c_int * count)()
        address = self.lib.xenforeignmemory_map(
            self.handle,
            int(domid),
            self.PROT_READ_WRITE,
            count,
            (ctypes.c_ulong * count)(*gfns),
            errors,
        )
        if not address:
            error = ctypes.get_errno()
            raise OSError(error, "cannot map guest memory: %s" % os.strerror(error))
        for gfn, error in zip(gfns, errors):
            if error:
                self.unmap(address, count)
                error = abs(error)
                raise OSError(
                    error, "cannot map gfn %x: %s" % (gfn, os.strerror(error))
                )
        return address, self.memory_view(address, count * PAGE_SIZE, self.PyBUF_WRITE)

    def unmap(self, address, pages):
        self.lib.xenforeignmemory_unmap(self.handle, address, pages)

    def map_ioreq(self, domid, server_id):
        """Map Xen's ioreq resource, which is not an ordinary guest GFN when the server is enabled."""
        fn = self.lib.xenforeignmemory_map_resource
        fn.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint16,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_int,
            ctypes.c_int,
        ]
        fn.restype = ctypes.c_void_p
        address = ctypes.c_void_p()
        # memory.h: resource_ioreq_server = 0, frame_ioreq(0) = 1 (frame 0 is the buffered ring).
        resource = fn(
            self.handle,
            int(domid),
            0,
            server_id,
            1,
            1,
            ctypes.byref(address),
            self.PROT_READ_WRITE,
            0,
        )
        if not resource:
            raise xen_error("xenforeignmemory_map_resource")
        area = self.memory_view(address.value, PAGE_SIZE, self.PyBUF_WRITE)
        return resource, area

    def unmap_ioreq(self, resource):
        fn = self.lib.xenforeignmemory_unmap_resource
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fn.restype = ctypes.c_int
        xen_check(fn(self.handle, resource), "xenforeignmemory_unmap_resource")

    def close(self):
        self.lib.xenforeignmemory_close(self.handle)


def xen_error(operation):
    error = ctypes.get_errno()
    return OSError(error, "%s: %s" % (operation, os.strerror(error)))


def xen_check(result, operation):
    if result < 0:
        raise xen_error(operation)
    return result


def xen_library(name, signatures):
    lib = ctypes.CDLL("lib%s.so.1" % name, use_errno=True)
    for suffix, result, args in signatures:
        fn = getattr(lib, name + "_" + suffix)
        fn.restype, fn.argtypes = result, args
    return lib


class IoreqServer:
    """A secondary emulator for one four-byte rendezvous register. It never acquires guest xenbus bindings."""

    def __init__(self, domid, io_port, memory):
        handle, uint, ushort = ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint16
        integer, ulonglong = ctypes.c_int, ctypes.c_uint64
        self.domid, self.io_port, self.memory = int(domid), io_port, memory
        self.dm_handle = self.evt_handle = self.server_id = None
        self.resource = self.area = self.fd = None
        self.enabled = False
        self.ports = {}
        self.next_bind_check = 0.0
        self.dm = xen_library(
            "xendevicemodel",
            [
                ("open", handle, [handle, uint]),
                ("close", integer, [handle]),
                (
                    "create_ioreq_server",
                    integer,
                    [handle, ushort, integer, ctypes.POINTER(ushort)],
                ),
                ("destroy_ioreq_server", integer, [handle, ushort, ushort]),
                ("set_ioreq_server_state", integer, [handle, ushort, ushort, integer]),
                (
                    "map_io_range_to_ioreq_server",
                    integer,
                    [handle, ushort, ushort, integer, ulonglong, ulonglong],
                ),
            ],
        )
        self.evt = xen_library(
            "xenevtchn",
            [
                ("open", handle, [handle, uint]),
                ("close", integer, [handle]),
                ("fd", integer, [handle]),
                ("bind_interdomain", integer, [handle, uint, uint]),
                ("pending", integer, [handle]),
                ("notify", integer, [handle, uint]),
                ("unmask", integer, [handle, uint]),
            ],
        )
        try:
            self.dm_handle = self.dm.xendevicemodel_open(None, 0)
            if not self.dm_handle:
                raise xen_error("xendevicemodel_open")
            self.evt_handle = self.evt.xenevtchn_open(None, 0)
            if not self.evt_handle:
                raise xen_error("xenevtchn_open")
            server_id = ushort()
            xen_check(
                self.dm.xendevicemodel_create_ioreq_server(
                    self.dm_handle, self.domid, 0, ctypes.byref(server_id)
                ),
                "xendevicemodel_create_ioreq_server",
            )
            self.server_id = server_id.value
            self.resource, self.area = memory.map_ioreq(self.domid, self.server_id)
            # Xen fills vp_eport only when enabled. Map the range last, once all response paths are ready.
            xen_check(
                self.dm.xendevicemodel_set_ioreq_server_state(
                    self.dm_handle, self.domid, self.server_id, 1
                ),
                "xendevicemodel_set_ioreq_server_state",
            )
            self.enabled = True
            self.refresh_ports()
            self.fd = xen_check(self.evt.xenevtchn_fd(self.evt_handle), "xenevtchn_fd")
            xen_check(
                self.dm.xendevicemodel_map_io_range_to_ioreq_server(
                    self.dm_handle, self.domid, self.server_id, 0, io_port, io_port + 3
                ),
                "xendevicemodel_map_io_range_to_ioreq_server",
            )
        except BaseException:
            self.close()
            raise
        log("listening on i/o port %#x (domain %s)" % (io_port, domid))

    def refresh_ports(self):
        """Bind Xen's per-vCPU endpoints, including vCPUs added after startup."""
        if time.monotonic() < self.next_bind_check:
            return
        self.next_bind_check = time.monotonic() + 1.0
        bound = set(self.ports.values())
        for offset in range(0, PAGE_SIZE, IOREQ.size):
            remote = struct.unpack_from("<I", self.area, offset + 24)[0]
            if remote and offset not in bound:
                local = xen_check(
                    self.evt.xenevtchn_bind_interdomain(
                        self.evt_handle, self.domid, remote
                    ),
                    "xenevtchn_bind_interdomain",
                )
                self.ports[local] = offset

    def dispatch(self, offset, link):
        """Complete even unsupported requests so a stray access cannot leave a vCPU blocked."""
        flags = self.area[offset + IOREQ_STATE_OFFSET]
        if flags & 0xF != IOREQ_READY:
            return
        self.area[offset + IOREQ_STATE_OFFSET] = (flags & 0xF0) | IOREQ_INPROCESS
        addr, data, count, size, remote, pad, flags, kind = IOREQ.unpack_from(
            self.area, offset
        )
        try:
            scalar = (
                kind == IOREQ_TYPE_PIO
                and addr == self.io_port
                and size == 4
                and count == 1
                and not flags & IOREQ_DATA_IS_PTR
            )
            if scalar:
                if flags & IOREQ_READ:
                    struct.pack_into(
                        "<Q", self.area, offset + 8, link.accepted_pfn(str(self.domid))
                    )
                else:
                    # Keep the issuing vCPU stopped until mapping/unmapping finishes, especially on shutdown.
                    link.announce(str(self.domid), data & INDEX_MASK)
            elif flags & IOREQ_READ and not flags & IOREQ_DATA_IS_PTR:
                struct.pack_into("<Q", self.area, offset + 8, 0xFFFFFFFFFFFFFFFF)
        finally:
            # Aligned fields and x86 TSO: data is visible before the response state and notification.
            self.area[offset + IOREQ_STATE_OFFSET] = (flags & 0xF0) | IORESP_READY

    def service(self, link):
        # xenevtchn_pending may block even with O_NONBLOCK on some kernels. Always select before calling it.
        while select.select([self.fd], [], [], 0)[0]:
            local = xen_check(
                self.evt.xenevtchn_pending(self.evt_handle), "xenevtchn_pending"
            )
            offset = self.ports.get(local)
            try:
                if offset is not None:
                    try:
                        self.dispatch(offset, link)
                    finally:
                        xen_check(
                            self.evt.xenevtchn_notify(self.evt_handle, local),
                            "xenevtchn_notify",
                        )
            finally:
                xen_check(
                    self.evt.xenevtchn_unmask(self.evt_handle, local),
                    "xenevtchn_unmask",
                )

    def drain(self):
        """After disabling new requests, wake vCPUs waiting for a response, including an interrupted notification."""
        self.next_bind_check = 0.0
        self.refresh_ports()
        pending = []
        for local, offset in self.ports.items():
            flags = self.area[offset + IOREQ_STATE_OFFSET]
            state = flags & 0xF
            if state not in (IOREQ_READY, IOREQ_INPROCESS, IORESP_READY):
                continue
            if state != IORESP_READY:
                # Don't attach new rings during exit. An unfinished scalar IN sees a detached register.
                if flags & IOREQ_READ and not flags & IOREQ_DATA_IS_PTR:
                    struct.pack_into("<Q", self.area, offset + 8, 0xFFFFFFFFFFFFFFFF)
                self.area[offset + IOREQ_STATE_OFFSET] = (flags & 0xF0) | IORESP_READY
            xen_check(
                self.evt.xenevtchn_notify(self.evt_handle, local), "xenevtchn_notify"
            )
            pending.append(offset)
        if not pending:
            return
        log("completing %d pending i/o requests before exit" % len(pending))
        deadline = time.monotonic() + IOREQ_DRAIN_TIMEOUT
        while pending:
            pending = [
                offset
                for offset in pending
                if self.area[offset + IOREQ_STATE_OFFSET] & 0xF
            ]
            if not pending:
                break
            if time.monotonic() >= deadline:
                log(
                    "timed out waiting for %d i/o responses to be consumed"
                    % len(pending)
                )
                break
            time.sleep(0.001)

    def close(self):
        # Destroying a server frees its event channels; it isn't a substitute for notifying a blocked vCPU.
        # Disable first so no new requests race with the final responses, and retain the request page until done.
        if self.enabled:
            try:
                xen_check(
                    self.dm.xendevicemodel_set_ioreq_server_state(
                        self.dm_handle, self.domid, self.server_id, 0
                    ),
                    "xendevicemodel_set_ioreq_server_state",
                )
                self.enabled = False
                self.drain()
            except OSError as e:
                if e.errno not in (errno.ESRCH, errno.ENOENT):
                    log("cannot drain ioreq server: %s" % e)
        # A server owned by dom0 outlives its process unless explicitly destroyed.
        if self.server_id is not None:
            result = self.dm.xendevicemodel_destroy_ioreq_server(
                self.dm_handle, self.domid, self.server_id
            )
            if result < 0 and ctypes.get_errno() not in (errno.ESRCH, errno.ENOENT):
                log(
                    "cannot destroy ioreq server: %s"
                    % xen_error("destroy_ioreq_server")
                )
            elif result >= 0:
                log("stopped ioreq server (domain %s)" % self.domid)
            self.server_id = None
            self.enabled = False
        if self.area is not None:
            self.area.release()
            self.area = None
        try:
            if self.resource is not None:
                self.memory.unmap_ioreq(self.resource)
                self.resource = None
        finally:
            if self.evt_handle:
                self.evt.xenevtchn_close(self.evt_handle)
                self.evt_handle = None
            if self.dm_handle:
                self.dm.xendevicemodel_close(self.dm_handle)
                self.dm_handle = None
            self.fd = None


class RingError(Exception):
    """The shared area can't be used (any more)."""


class SharedRings:
    """dom0's end of xenkd's rings (see xenkd/xenkd_shm.h), with separate header and ring buffers. Any buffers work,
    so this can be tested without a guest.

    x86 is TSO, so aligned 32-bit loads and stores done in program order are all the ordering needed. dom0's own
    indices are kept here, and only written to the header: the guest can't confuse us by changing them.
    """

    def __init__(self, header, area, generation):
        """Attach: the header must still be the one announced with this generation."""
        self.check_header(header, generation)
        if len(area) != SHM_RING_PAGES * PAGE_SIZE:
            raise RingError("expected %d ring pages" % SHM_RING_PAGES)
        self.header = memoryview(header)
        self.words = words = self.header.cast("I")
        self.area = memoryview(area)
        self.data_words = self.area.cast("I")
        self.generation = generation

        # Drop anything stale, and rewrite all of our fields before claiming the area, so that a stale write from an
        # earlier attachment is harmless.
        self.tx_cons = words[SHM_TX_CONS // 4] = words[SHM_TX_PROD // 4]
        self.rx_prod = words[SHM_RX_PROD // 4] = words[SHM_RX_CONS // 4]
        self.beats = (words[SHM_DOM0_HEARTBEAT // 4] + 1) & INDEX_MASK
        words[SHM_DOM0_HEARTBEAT // 4] = self.beats
        words[SHM_DOM0_GENERATION // 4] = generation

    @staticmethod
    def check_header(header, generation):
        """The versioned signature fixes all geometry; generation identifies this initialization."""
        if len(header) != PAGE_SIZE:
            raise RingError("expected one header page")
        signature, actual_generation = struct.unpack_from("<II", header, 0)
        if signature != SHM_SIGNATURE:
            raise RingError("unsupported shared area signature %08x" % signature)
        if generation == 0 or actual_generation != generation:
            raise RingError(
                "generation %x, not %x as announced" % (actual_generation, generation)
            )

    def check(self):
        """Make sure the guest still uses the area as announced: called before every batch of writes, to keep the
        window in which we could write into pages Windows has reused as small as possible."""
        signature = self.words[SHM_SIGNATURE_OFFSET // 4]
        generation = self.words[SHM_GENERATION_OFFSET // 4]
        if signature != SHM_SIGNATURE or generation != self.generation:
            raise RingError(
                "the guest let go of it (signature %08x, generation %x)"
                % (signature, generation)
            )

    def receive(self):
        """Heartbeat, and take the frames the guest sent."""
        self.check()
        words = self.words
        self.beats = (self.beats + 1) & INDEX_MASK
        words[SHM_DOM0_HEARTBEAT // 4] = self.beats
        prod = words[SHM_TX_PROD // 4]
        if prod == self.tx_cons:
            return []
        if (prod - self.tx_cons) & INDEX_MASK > SHM_TX_SLOTS:
            raise RingError("bad TX producer %d (consumer %d)" % (prod, self.tx_cons))
        frames = []
        while self.tx_cons != prod:
            offset = (self.tx_cons % SHM_TX_SLOTS) * SHM_SLOT_SIZE
            length = self.data_words[offset // 4]
            if length > MAX_FRAME:
                raise RingError("the guest sent a frame of %d bytes" % length)
            # Empty slots are skipped, but consumed.
            if length:
                frames.append(bytes(self.area[offset + 4 : offset + 4 + length]))
            self.tx_cons = (self.tx_cons + 1) & INDEX_MASK
        words[SHM_TX_CONS // 4] = self.tx_cons
        return frames

    def send(self, frame):
        """Queue a frame for the guest. Returns False when the RX ring is full, so the caller drops the frame."""
        if len(frame) > MAX_FRAME:
            raise ValueError("%d-byte frame" % len(frame))
        self.check()
        words = self.words
        cons = words[SHM_RX_CONS // 4]
        pending = (self.rx_prod - cons) & INDEX_MASK
        if pending > SHM_RX_SLOTS:
            raise RingError("bad RX consumer %d (producer %d)" % (cons, self.rx_prod))
        if pending == SHM_RX_SLOTS:
            return False
        offset = SHM_RX_OFFSET + (self.rx_prod % SHM_RX_SLOTS) * SHM_SLOT_SIZE
        self.area[offset + 4 : offset + 4 + len(frame)] = frame
        self.data_words[offset // 4] = len(frame)
        self.rx_prod = (self.rx_prod + 1) & INDEX_MASK
        words[SHM_RX_PROD // 4] = self.rx_prod
        return True

    def detach(self):
        """Tell the guest right away, if the area is still its, and stop using the buffer."""
        try:
            self.check()
            self.words[SHM_DOM0_GENERATION // 4] = 0
        except RingError:
            pass
        self.words.release()
        self.header.release()
        self.data_words.release()
        self.area.release()


class DropCounter:
    def __init__(self, what):
        self.what = what
        self.count = 0

    def drop(self):
        self.count += 1
        if self.count == 1 or self.count % 100 == 0:
            log("%s, %d dropped so far" % (self.what, self.count))


class GuestLink:
    """The guest's rings: attached by a PFN write, detached by all ones or when the area goes away."""

    def __init__(self, args, memory=None):
        self.args = args
        try:
            self.memory = memory or ForeignMemory()
        except OSError as e:
            raise SystemExit("cannot map guest memory: %s" % e)
        self.domid = self.gfn = self.rings = self.mapping = self.error = None
        self.last_traffic = 0.0
        self.full = DropCounter("guest RX ring full")
        self.too_large = DropCounter("frame too large for the guest")

    @property
    def attached(self):
        return self.rings is not None

    def accepted_pfn(self, domid):
        """Readback acknowledges an attached, still-valid header, not merely receipt of a port write."""
        if self.attached and self.domid == domid:
            try:
                self.rings.check()
                return self.gfn
            except RingError as e:
                self.detach(str(e))
        return IO_DETACH

    def announce(self, domid, gfn):
        if gfn == IO_DETACH:
            self.detach("the guest closed the rings")
            self.error = None
            return
        if self.attached and (self.domid, self.gfn) == (domid, gfn):
            try:
                self.rings.check()
                return
            except RingError as e:
                self.detach(str(e))

        mappings = []
        try:
            # Retain the header mapping; the PFN array contains only packet-ring pages.
            address, header = self.memory.map(domid, [gfn])
            mappings.append((address, header, 1))
            generation = struct.unpack_from("<I", header, SHM_GENERATION_OFFSET)[0]
            SharedRings.check_header(header, generation)
            gfns = list(
                struct.unpack_from("<%dQ" % SHM_RING_PAGES, header, SHM_GFN_OFFSET)
            )
            if gfn in gfns or len(set(gfns)) != SHM_RING_PAGES:
                raise RingError("ring PFNs overlap each other or the header")
            if self.attached:
                self.detach("the guest announced generation %x" % generation)
            address, area = self.memory.map(domid, gfns)
            mappings.append((address, area, SHM_RING_PAGES))
            # Both mappings are now live. Validate the retained header again before publishing attachment.
            SharedRings.check_header(header, generation)
            current_gfns = list(
                struct.unpack_from("<%dQ" % SHM_RING_PAGES, header, SHM_GFN_OFFSET)
            )
            if current_gfns != gfns:
                raise RingError("the page list changed while mapping the shared area")
            rings = SharedRings(header, area, generation)
        except BaseException as e:
            for address, view, pages in reversed(mappings):
                view.release()
                self.memory.unmap(address, pages)
            if not isinstance(e, (OSError, RingError)):
                raise
            # The guest announces every second until we attach, so say it once.
            error = "cannot attach to the shared area at gfn %x: %s" % (gfn, e)
            if error != self.error:
                self.error = error
                log(error)
            return
        self.domid, self.gfn, self.rings, self.error = domid, gfn, rings, None
        self.mapping = mappings
        self.last_traffic = time.monotonic()
        log(
            "attached to the shared area at gfn %x (generation %x, %d ring pages,"
            " %d TX and %d RX slots)"
            % (gfn, generation, SHM_RING_PAGES, SHM_TX_SLOTS, SHM_RX_SLOTS)
        )

    def detach(self, reason):
        if not self.attached:
            return
        self.rings.detach()
        for address, view, pages in reversed(self.mapping):
            view.release()
            self.memory.unmap(address, pages)
        self.rings = self.mapping = None
        log("detached from the shared area: %s" % reason)

    def follow(self, domain):
        """Detach when the domain we're attached to goes away."""
        if self.attached and domain.domid != self.domid:
            self.detach("domain %s went away" % self.domid)

    def busy(self):
        """Whether frames flowed in either direction within ACTIVE_PERIOD."""
        return self.attached and time.monotonic() - self.last_traffic < ACTIVE_PERIOD

    def timeout(self, limit):
        """How long select() may wait before the rings need polling: at most limit, unless busy (when the domain check
        that limit is for waits)."""
        if self.busy():
            # KDNET waits for the answer to most packets, so any wait for the next poll adds to every round trip.
            return 0.0 if self.args.fast else ACTIVE_POLL_INTERVAL
        return min(limit, IDLE_POLL_INTERVAL) if self.attached else limit

    def poll(self):
        """Heartbeat, and return the frames from the guest."""
        if not self.attached:
            return []
        try:
            frames = self.rings.receive()
        except RingError as e:
            self.detach(str(e))
            return []
        if frames:
            self.last_traffic = time.monotonic()
        return frames

    def send(self, frame):
        """Pass a frame to the guest, or drop it if the guest can't take it now."""
        if not self.attached:
            return
        if len(frame) > MAX_FRAME:
            self.too_large.drop()
            return
        try:
            sent = self.rings.send(frame)
        except RingError as e:
            self.detach(str(e))
            return
        if sent:
            self.last_traffic = time.monotonic()
        else:
            self.full.drop()

    def close(self):
        self.detach("the bridge is exiting")
        self.memory.close()


def parse_io_port(text):
    try:
        port = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("expected an I/O port, such as 0xec")
    if port <= 0 or port > 0xFFFC or port & 3:
        raise argparse.ArgumentTypeError(
            "I/O port must be nonzero and four-byte aligned, at most 0xfffc"
        )
    return port


def parse_address(text):
    host, separator, port = text.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise argparse.ArgumentTypeError("expected HOST:PORT, got %r" % text)
    return host, int(port)


def resolve_ipv4(host):
    """A host name or address, as an IPv4 address in network order. Raises OSError."""
    return socket.inet_aton(socket.gethostbyname(host))


def checksum(data):
    """The Internet checksum (RFC 1071) of data."""
    if len(data) % 2:
        data += b"\0"
    # 2**16 is 1 modulo 0xFFFF, so the ones' complement sum of the 16-bit words is data, read as one big number, modulo
    # 0xFFFF: computed in C rather than word by word. Except that end-around carry never gives 0 for a nonzero sum.
    number = int.from_bytes(data, "big")
    total = number % 0xFFFF or (0xFFFF if number else 0)
    return ~total & 0xFFFF


class UdpProxy:
    """Stand in for KDNET's network: answer its ARP and carry its UDP traffic over a dom0 socket.

    Restarting the bridge mustn't break a debug session, so the socket uses a fixed port: WinDbg keeps seeing the target
    at the same address. A restarted bridge knows the debugger's address from --destination (the guest's HOST_IP and
    port) and the guest's from --guest-ip (its TARGET_IP), if given, and learns the rest again from its next ARP or UDP
    packet.
    """

    def __init__(self, args):
        self.args = args
        self.socket = None
        # The guest's end (MAC, IP, UDP port), and the debugger as the guest addresses it (IP, UDP port).
        self.guest_mac = self.guest_ip = self.guest_port = None
        self.host_ip = self.host_port = None
        self.destination = None
        self.ip_id = 0
        self.dhcp_logged = False
        self.corrupted = DropCounter("damaged frame from the guest")

        if args.guest_ip:
            self.guest_ip = socket.inet_aton(args.guest_ip)
        if args.debugger is not None:
            # The guest's HOST_IP and HOST_PORT are the debugger's address, until it says otherwise.
            try:
                self.host_ip = resolve_ipv4(args.debugger[0])
            except OSError:
                pass
            self.host_port = args.debugger[1]
        if args.destination is not None:
            # Replies can go out before the guest has sent anything.
            try:
                self.destination = (
                    resolve_ipv4(args.destination[0]),
                    args.destination[1],
                )
            except OSError as e:
                raise SystemExit("bad --destination %s: %s" % (args.destination[0], e))
            self.host_ip, self.host_port = self.destination
            log(
                "only forwarding UDP the guest sends to %s:%d"
                % (socket.inet_ntoa(self.destination[0]), self.destination[1])
            )
        else:
            log("forwarding UDP the guest sends to any address")
        if self.guest_ip is not None:
            log("only talking to guest %s" % socket.inet_ntoa(self.guest_ip))
        else:
            log("talking to any guest address")
        # Otherwise the socket opens once the guest says which port it talks to.
        if args.local_port or args.debugger is not None:
            self.open_socket(args.local_port or args.debugger[1])

    def open_socket(self, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Rebind right away after a restart, so the debugger keeps seeing the target at the same address.
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind(("0.0.0.0", port))
        except OSError as e:
            raise SystemExit(
                "cannot use udp port %d: %s (if the debugger runs in dom0, pick another"
                " one with --local-port)" % (port, e)
            )
        self.socket.setblocking(False)
        target = " at %s:%d" % self.args.debugger if self.args.debugger else ""
        log("talking to the debugger%s from dom0 udp port %d" % (target, port))

    def debugger(self):
        if self.args.debugger is not None:
            return self.args.debugger
        return socket.inet_ntoa(self.host_ip), self.host_port

    def from_guest(self, frame):
        """Handle a frame from the guest, and return the frames to send back to it."""
        ethertype = frame[12:14]
        if ethertype == ETHERTYPE_ARP and len(frame) >= 42:
            return self.arp(frame)
        if ethertype != ETHERTYPE_IPV4 or len(frame) < 34 or frame[23] != IPPROTO_UDP:
            return []
        header_length = (frame[14] & 0x0F) * 4
        udp = 14 + header_length
        if len(frame) < udp + 8:
            return []
        source_port, destination_port, length = struct.unpack(
            "!HHH", frame[udp : udp + 6]
        )
        # The guest's other traffic (NetBIOS, mDNS...) isn't for the debugger, and must not change where replies go.
        if self.guest_ip is not None and frame[26:30] != self.guest_ip:
            return []
        problem = self.check_udp(frame, header_length, length)
        if problem is not None:
            # Don't hand the debugger something it can only reject ("Bad packet sent from ...").
            self.corrupted.drop()
            if self.args.verbose:
                log("dropping a damaged frame from the guest (%s)" % problem)
            return []
        if destination_port == DHCP_SERVER_PORT:
            if not self.dhcp_logged:
                self.dhcp_logged = True
                log(
                    "the guest is asking for DHCP, which the bridge doesn't answer: give it"
                    " NO_DHCP (and TARGET_IP) to skip the wait for a link-local address"
                )
            return []
        if self.destination not in (None, (frame[30:34], destination_port)):
            return []

        guest = frame[6:12], frame[26:30], source_port
        host = frame[30:34], destination_port
        if guest + host != (
            self.guest_mac,
            self.guest_ip,
            self.guest_port,
            self.host_ip,
            self.host_port,
        ):
            self.guest_mac, self.guest_ip, self.guest_port = guest
            self.host_ip, self.host_port = host
            log(
                "guest %s:%d talks to %s:%d, forwarding to %s:%d"
                % (
                    (socket.inet_ntoa(self.guest_ip), self.guest_port)
                    + (socket.inet_ntoa(self.host_ip), self.host_port)
                    + self.debugger()
                )
            )
        if self.socket is None:
            self.open_socket(self.host_port)
        try:
            self.socket.sendto(frame[udp + 8 : udp + length], self.debugger())
        except OSError as e:
            log("cannot send to the debugger: %s" % e)
        return []

    @staticmethod
    def check_udp(frame, header_length, length):
        """Check a guest frame's IPv4 and UDP headers, and return what's wrong with it (or None)."""
        ip = frame[14 : 14 + header_length]
        total_length = struct.unpack("!H", ip[2:4])[0]
        if header_length < 20 or len(frame) < 14 + total_length:
            return "truncated"
        # A zero checksum means it wasn't filled in (left to an offload that doesn't exist here), not that it's wrong.
        if ip[10:12] != b"\0\0" and checksum(ip) != 0:
            return "bad IPv4 header checksum"
        if length < 8 or header_length + length > total_length:
            return "bad UDP length"
        udp = frame[14 + header_length : 14 + header_length + length]
        if udp[6:8] != b"\0\0":
            pseudo_header = ip[12:20] + struct.pack("!BBH", 0, IPPROTO_UDP, length)
            if checksum(pseudo_header + udp) != 0:
                return "bad UDP checksum"
        return None

    def arp(self, frame):
        operation = struct.unpack("!H", frame[20:22])[0]
        sender_mac, sender_ip, target_ip = frame[22:28], frame[28:32], frame[38:42]
        # Don't answer probes (no sender address yet) or announcements: they check that nobody else owns that address.
        if operation != ARP_REQUEST or sender_ip in (b"\0\0\0\0", target_ip):
            return []
        # Only the guest's KDNET address, asking for the debugger's, is answered, so that other hosts' ARP doesn't change
        # where replies go.
        if self.guest_ip is not None and sender_ip != self.guest_ip:
            return []
        if self.destination is not None and target_ip != self.destination[0]:
            return []
        # A restarted bridge may see ARP before any UDP, when it has to learn the guest's address (--guest-ip '').
        self.guest_mac, self.guest_ip = sender_mac, sender_ip
        if self.host_ip is None:
            self.host_ip = target_ip
        reply = (
            sender_mac
            + PROXY_MAC
            + ETHERTYPE_ARP
            + struct.pack("!HHBBH", 1, 0x0800, 6, 4, ARP_REPLY)
            + PROXY_MAC
            + target_ip
            + sender_mac
            + sender_ip
        )
        return [reply.ljust(60, b"\0")]

    def from_debugger(self):
        """Read a datagram from the debugger, and return it as a frame for the guest (or None)."""
        try:
            payload, _ = self.socket.recvfrom(65535)
        except (BlockingIOError, ConnectionRefusedError):
            return None
        if None in (self.guest_mac, self.guest_ip, self.host_ip, self.host_port):
            if self.args.verbose:
                log("dropping %d bytes from the debugger: no guest yet" % len(payload))
            return None
        # KDNET uses the same port on both ends, so that's the best guess until the guest says otherwise.
        guest_port = self.guest_port or self.host_port
        length = 8 + len(payload)
        self.ip_id = (self.ip_id + 1) & 0xFFFF

        def udp_header(udp_checksum):
            return struct.pack(
                "!HHHH", self.host_port, guest_port, length, udp_checksum
            )

        def ip_header(ip_checksum):
            return struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + length,
                self.ip_id,
                0,
                64,
                IPPROTO_UDP,
                ip_checksum,
                self.host_ip,
                self.guest_ip,
            )

        pseudo_header = (
            self.host_ip + self.guest_ip + struct.pack("!BBH", 0, IPPROTO_UDP, length)
        )
        udp_checksum = checksum(pseudo_header + udp_header(0) + payload) or 0xFFFF
        return (
            self.guest_mac
            + PROXY_MAC
            + ETHERTYPE_IPV4
            + ip_header(checksum(ip_header(0)))
            + udp_header(udp_checksum)
            + payload
        )


def run(args, stopping):
    key = follow_key()
    domain = Domain(key, resolve_domain(args.domain, key))
    link = GuestLink(args)
    server = proxy = None
    error = None

    def send_to_guest(frame):
        if args.verbose:
            log("proxy > guest: %s" % describe_frame(frame))
        link.send(frame)

    try:
        proxy = UdpProxy(args)
        while not stopping():
            # Domain lookups run commands, so defer them while packet traffic is active.
            changed = domain.poll() if not link.busy() else False
            link.follow(domain)
            if server is not None and str(server.domid) != domain.domid:
                server.close()
                server = None
            if changed and domain.domid is not None:
                smbios_uuid = read_domain(domain.domid, "vm")
                if smbios_uuid and UUID_FORMAT.match(smbios_uuid):
                    proxy.guest_mac = kdnet_mac(smbios_uuid)
                    log(
                        "guest MAC is %s (from domain UUID %s)"
                        % (format_mac(proxy.guest_mac), smbios_uuid)
                    )
            if server is None and domain.domid is not None:
                try:
                    server = IoreqServer(domain.domid, args.io_port, link.memory)
                    error = None
                except OSError as e:
                    # A domain can disappear between the identity check and server creation.
                    if e.errno not in (errno.ESRCH, errno.ENOENT):
                        raise
                    message = "waiting for domain %s: %s" % (domain.domid, e)
                    if error != message:
                        log(message)
                        error = message
                    domain.domid = None
            if server is not None:
                server.refresh_ports()
            readers = [
                fd
                for fd in (proxy.socket, server.fd if server else None)
                if fd is not None
            ]
            timeout = link.timeout(domain.time_to_poll())
            spin_until = time.monotonic() + SPIN_SLICE if timeout == 0 else 0.0
            while not stopping():
                readable = select.select(readers, [], [], timeout)[0]
                config_read = server is not None and server.fd in readable
                if config_read:
                    try:
                        server.service(link)
                    except OSError:
                        if read_domain(domain.domid, key) == domain.value:
                            raise
                        # The target vanished while a response was being sent. Recreate the server for its next domid.
                        link.detach("domain %s went away" % domain.domid)
                        server.close()
                        server = None
                        domain.domid = None
                        domain.next_check = 0.0
                        break
                for frame in link.poll():
                    if args.verbose:
                        log("guest > proxy: %s" % describe_frame(frame))
                    for reply in proxy.from_guest(frame):
                        send_to_guest(reply)
                if proxy.socket in readable:
                    frame = proxy.from_debugger()
                    if frame is not None and link.attached:
                        send_to_guest(frame)
                if config_read or time.monotonic() >= spin_until:
                    break
    finally:
        # Release the shared rings before close() completes any outstanding shutdown OUT.
        try:
            link.detach("the bridge is exiting")
        finally:
            try:
                if server is not None:
                    server.close()
            finally:
                link.memory.close()
                if proxy is not None and proxy.socket is not None:
                    proxy.socket.close()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 1)[1],
    )
    parser.add_argument(
        "domain",
        help="the domain to follow: its UUID with XAPI or name with xl, or its"
        " domid or other identifier while it runs",
    )
    parser.add_argument(
        "-d",
        "--debugger",
        type=parse_address,
        metavar="HOST:PORT",
        help="the debugger's address (default: the guest's HOST_IP and port)",
    )
    parser.add_argument(
        "--guest-ip",
        metavar="IP",
        help="only talk to this guest address, its TARGET_IP as set by Enable-XenKd.ps1"
        " -TargetIp (default: any, learned from the guest's first packet)",
    )
    parser.add_argument(
        "--destination",
        type=parse_address,
        default=DEFAULT_DESTINATION,
        metavar="IP:PORT",
        help="only forward UDP the guest sends to this address, its HOST_IP and port as"
        " set by Enable-XenKd.ps1 -HostIp and -Port, and only answer ARP for the IP"
        " (default: %(default)s)",
    )
    parser.add_argument(
        "--local-port",
        type=int,
        metavar="PORT",
        help="the dom0 UDP port to talk to the debugger from (default: the"
        " debugger's port). It stays the same across restarts of the bridge, so that"
        " the debugger keeps seeing the target at the same address",
    )
    parser.add_argument(
        "--io-port",
        type=parse_io_port,
        default=DEFAULT_IO_PORT,
        metavar="PORT",
        help="rendezvous I/O port (default: 0xec); must match the guest's XENKD_IOPORT"
        " load option and have four reserved, unused bytes",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="while frames flow, poll the guest's rings continuously instead of every"
        " %d us: about 1.5 times the throughput, but keeps a dom0 CPU busy until"
        " %g s after the last frame" % (ACTIVE_POLL_INTERVAL * 1e6, ACTIVE_PERIOD),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log every frame passed in either direction",
    )
    args = parser.parse_args()

    stop_requested = False

    def request_stop(signum, frame):
        nonlocal stop_requested
        # Don't raise inside an ioreq update, mapping operation or cleanup. Finish the current operation first.
        stop_requested = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    try:
        run(args, lambda: stop_requested)
    except KeyboardInterrupt:
        pass
    except (OSError, AttributeError) as e:
        raise SystemExit("cannot run the bridge: %s" % e)


if __name__ == "__main__":
    main()
