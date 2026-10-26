#!/usr/bin/env python3
"""Bridge a guest's xenkd to the debugger, over UDP from dom0.

xenkd gives KDNET a network card made of two rings of Ethernet frames in guest memory (see xenkd/xenkd_shm.h), and
announces where they are on the guest's PV console. The bridge maps the rings from dom0, polls them, and stands in for
KDNET's network: it answers the guest's ARP, forwards its UDP payloads to the debugger from an ordinary UDP socket, and
wraps the debugger's replies back into frames. The debugger only needs to reach dom0 on one UDP port: the guest's
HOST_IP:port, or --debugger. DHCP isn't answered, so the guest needs NO_DHCP and TARGET_IP (as Enable-XenKd.ps1 sets
them). Attach with `windbg -k net:port=<port>,key=<key>`.

The bridge can be restarted during a debug session: it talks to the debugger from a fixed port, knows the guest's
address right away (its MAC follows from the domain's UUID, its IP is --guest-ip), and xenkd announces its rings again
within about 3 s of the bridge going away.

It follows the guest across reboots, which change its domid: by its UUID on XAPI hosts (XenServer, XCP-ng), where names
can repeat, and by its name with xl, where `xl create` gives a new UUID unless the config sets one. A domid, or the
other of the two, is looked up from the running domain at startup.

Run in dom0 as root. Needs xenstore-read, xenstore-list and libxenforeignmemory. Don't run `xl console` on the same
domain at the same time: it would read the same pty, and could swallow xenkd's announces.
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
import tty
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
# With --fast, how often to look up the domain, console and timeouts again while spinning.
SPIN_SLICE = 0.001

# The shared area, as laid out in xenkd/xenkd_shm.h: a header page, then the TX ring (guest to dom0) and the RX ring
# (dom0 to guest). Each slot is a 32-bit length followed by the frame. Indices are free-running 32-bit counters.
PAGE_SIZE = 4096
SHM_MAGIC = 0x53444B58  # "XKDS"
SHM_VERSION = 1
SHM_MAX_PAGES = 64
SHM_MAGIC_OFFSET = 0x000
SHM_GENERATION_OFFSET = 0x008
SHM_GFN_OFFSET = 0x020
SHM_TX_PROD = 0x400
SHM_TX_CONS = 0x440
SHM_RX_PROD = 0x480
SHM_RX_CONS = 0x4C0
SHM_DOM0_GENERATION = 0x500
SHM_DOM0_HEARTBEAT = 0x504
INDEX_MASK = 0xFFFFFFFF
# What xenkd writes on the console while dom0 isn't attached to its rings.
ANNOUNCE = re.compile(rb"xenkd-shm v1 gfn=([0-9a-f]+) gen=([0-9a-f]+)")
# Longer console lines aren't announces, and only their end is kept.
MAX_CONSOLE_LINE = 256

ETHERTYPE_IPV4 = b"\x08\x00"
ETHERTYPE_ARP = b"\x08\x06"
IPPROTO_UDP = 17
DHCP_SERVER_PORT = 67
ARP_REQUEST = 1
ARP_REPLY = 2
# What the guest sees as the MAC of every other host (locally administered).
PROXY_MAC = b"\x02\x00\x00\x6b\x64\x00"


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


class Console:
    """The PV console pty of the domain we follow, reopened whenever the domain is recreated (with a new domid and pty).

    It's only read: xenkd announces its rings there.
    """

    def __init__(self, key, value):
        """Follow the domain whose UUID (key "vm") or name (key "name") is value."""
        self.key, self.value = key, value
        self.fd = self.domid = self.path = self.status = None
        self.next_check = 0.0
        self.partial = b""

    def set_status(self, status):
        # Log state changes only, not every check.
        if status != self.status:
            self.status = status
            log(status)

    def console_path(self, domid):
        """The console pty of domain domid, if it's (still) the domain we follow."""
        if read_domain(domid, self.key) != self.value:
            return None
        return query("xenstore-read", "/local/domain/%s/console/tty" % domid)

    def poll(self):
        """Follow the domain: return True when its console was just (re)opened."""
        now = time.monotonic()
        if now < self.next_check:
            return False
        self.next_check = now + DOMAIN_CHECK_INTERVAL

        if self.fd is not None:
            # Usually still the same domain: confirming that is cheaper than a search.
            if self.console_path(self.domid) == self.path:
                return False
            self.close()
        domids = find_domains(self.key, self.value)
        if not domids:
            self.set_status("waiting for domain %s..." % self.value)
            return False
        path = self.console_path(domids[0])
        if path is None:
            self.set_status("waiting for the PV console of domain %s..." % domids[0])
            return False

        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
            # No line discipline or echo: echo would send the guest's output back to it.
            tty.setraw(fd)
        except OSError as e:
            self.set_status("cannot open %s: %s" % (path, e))
            return False
        self.fd, self.domid, self.path = fd, domids[0], path
        self.partial = b""
        self.set_status("attached to %s (domain %s)" % (path, self.domid))
        return True

    def time_to_poll(self):
        """How long until poll() has something to check."""
        return max(0.0, self.next_check - time.monotonic())

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
            self.set_status("detached from %s (domain %s)" % (self.path, self.domid))
        # Look for the domain again soon: a rebooting guest is back within seconds.
        self.next_check = min(self.next_check, time.monotonic() + 1.0)

    def read_lines(self):
        """Read what's available, and return the complete lines in it."""
        try:
            data = os.read(self.fd, 4096)
        except BlockingIOError:
            return []
        except OSError as e:
            if e.errno != errno.EIO:
                raise
            data = b""
        if not data:
            self.close()
            return []
        lines = (self.partial + data).split(b"\n")
        self.partial = lines.pop()[-MAX_CONSOLE_LINE:]
        return lines


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

    def close(self):
        self.lib.xenforeignmemory_close(self.handle)


class RingError(Exception):
    """The shared area can't be used (any more)."""


class SharedRings:
    """dom0's end of xenkd's rings (see xenkd/xenkd_shm.h), in a writable buffer holding the whole area. Any buffer
    works, so this can be tested without a guest.

    x86 is TSO, so aligned 32-bit loads and stores done in program order are all the ordering needed. dom0's own
    indices are kept here, and only written to the area: the guest can't confuse us by changing them.
    """

    def __init__(self, area, generation):
        """Attach: the header must still be the one announced with this generation."""
        self.area = memoryview(area)
        self.words = words = self.area.cast("I")
        page_count, self.slot_size, self.tx_slots, self.rx_slots = self.check_header(
            self.area, generation
        )
        if len(self.area) < page_count * PAGE_SIZE:
            raise RingError(
                "%d pages mapped, the guest says %d"
                % (len(self.area) // PAGE_SIZE, page_count)
            )
        self.generation = generation
        self.tx_offset = PAGE_SIZE
        self.rx_offset = PAGE_SIZE + self.tx_slots * self.slot_size

        # Drop anything stale, and rewrite all of our fields before claiming the area, so that a stale write from an
        # earlier attachment is harmless.
        self.tx_cons = words[SHM_TX_CONS // 4] = words[SHM_TX_PROD // 4]
        self.rx_prod = words[SHM_RX_PROD // 4] = words[SHM_RX_CONS // 4]
        self.beats = (words[SHM_DOM0_HEARTBEAT // 4] + 1) & INDEX_MASK
        words[SHM_DOM0_HEARTBEAT // 4] = self.beats
        words[SHM_DOM0_GENERATION // 4] = generation

    @staticmethod
    def check_header(header, generation):
        """Check the header of a shared area, and return its geometry: (page count, slot size, TX slots, RX slots)."""
        magic, version, actual_generation, page_count, slot_size, tx_slots, rx_slots = (
            struct.unpack_from("<7I", header, 0)
        )
        if magic != SHM_MAGIC:
            raise RingError("no shared area there (magic %08x)" % magic)
        if version != SHM_VERSION:
            raise RingError("unsupported shared area version %d" % version)
        if actual_generation != generation:
            raise RingError(
                "generation %x, not %x as announced" % (actual_generation, generation)
            )
        if (
            slot_size < 4 + MAX_FRAME
            or slot_size > PAGE_SIZE
            or slot_size & (slot_size - 1)
        ):
            raise RingError("bad slot size %d" % slot_size)
        for slots in (tx_slots, rx_slots):
            if slots == 0 or slots & (slots - 1):
                raise RingError("bad slot count %d" % slots)
        if (
            page_count > SHM_MAX_PAGES
            or page_count * PAGE_SIZE < PAGE_SIZE + (tx_slots + rx_slots) * slot_size
        ):
            raise RingError(
                "bad page count %d for %d+%d slots of %d bytes"
                % (page_count, tx_slots, rx_slots, slot_size)
            )
        return page_count, slot_size, tx_slots, rx_slots

    def check(self):
        """Make sure the guest still uses the area as announced: called before every batch of writes, to keep the
        window in which we could write into pages Windows has reused as small as possible."""
        magic = self.words[SHM_MAGIC_OFFSET // 4]
        generation = self.words[SHM_GENERATION_OFFSET // 4]
        if magic != SHM_MAGIC or generation != self.generation:
            raise RingError(
                "the guest let go of it (magic %08x, generation %x)"
                % (magic, generation)
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
        if (prod - self.tx_cons) & INDEX_MASK > self.tx_slots:
            raise RingError("bad TX producer %d (consumer %d)" % (prod, self.tx_cons))
        frames = []
        while self.tx_cons != prod:
            offset = self.tx_offset + (self.tx_cons % self.tx_slots) * self.slot_size
            length = words[offset // 4]
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
        if pending > self.rx_slots:
            raise RingError("bad RX consumer %d (producer %d)" % (cons, self.rx_prod))
        if pending == self.rx_slots:
            return False
        offset = self.rx_offset + (self.rx_prod % self.rx_slots) * self.slot_size
        self.area[offset + 4 : offset + 4 + len(frame)] = frame
        words[offset // 4] = len(frame)
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
    """The guest's rings: attached when xenkd announces them on the console, detached when they go away."""

    def __init__(self, args, memory=None):
        self.args = args
        try:
            self.memory = memory or ForeignMemory()
        except OSError as e:
            raise SystemExit("cannot map guest memory: %s" % e)
        self.domid = self.rings = self.mapping = self.error = None
        self.last_traffic = 0.0
        self.full = DropCounter("guest RX ring full")
        self.too_large = DropCounter("frame too large for the guest")

    @property
    def attached(self):
        return self.rings is not None

    def console(self, console, lines):
        """Handle lines from the guest's console, which may hold announces."""
        for line in lines:
            match = ANNOUNCE.search(line)
            if match:
                gfn, generation = int(match.group(1), 16), int(match.group(2), 16)
                self.announce(console.domid, gfn, generation)
            elif self.args.verbose and line.strip():
                log("console: %s" % line.decode(errors="replace").rstrip())

    def announce(self, domid, gfn, generation):
        if self.attached:
            # xenkd announced before it saw us: no need to reset the rings.
            if (self.domid, self.rings.generation) == (domid, generation):
                return
            self.detach("the guest announced generation %x" % generation)
        try:
            # The header lists the area's pages: map it alone first.
            address, header = self.memory.map(domid, [gfn])
            try:
                page_count = SharedRings.check_header(header, generation)[0]
                gfns = list(
                    struct.unpack_from("<%dQ" % page_count, header, SHM_GFN_OFFSET)
                )
            finally:
                header.release()
                self.memory.unmap(address, 1)
            if gfns[0] != gfn:
                raise RingError("the header says it's at gfn %x" % gfns[0])
            address, area = self.memory.map(domid, gfns)
            try:
                rings = SharedRings(area, generation)
            except Exception:
                area.release()
                self.memory.unmap(address, page_count)
                raise
        except (OSError, RingError) as e:
            # The guest announces every second until we attach, so say it once.
            error = "cannot attach to the shared area at gfn %x: %s" % (gfn, e)
            if error != self.error:
                self.error = error
                log(error)
            return
        self.domid, self.rings, self.error = domid, rings, None
        self.mapping = address, area, page_count
        self.last_traffic = time.monotonic()
        log(
            "attached to the shared area at gfn %x (generation %x, %d pages,"
            " %d TX and %d RX slots)"
            % (gfn, generation, page_count, rings.tx_slots, rings.rx_slots)
        )

    def detach(self, reason):
        if not self.attached:
            return
        self.rings.detach()
        address, area, page_count = self.mapping
        area.release()
        self.memory.unmap(address, page_count)
        self.rings = self.mapping = None
        log("detached from the shared area: %s" % reason)

    def follow(self, console):
        """Detach when the domain we're attached to goes away."""
        if self.attached and (console.fd is None or console.domid != self.domid):
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


def parse_address(text):
    host, separator, port = text.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise argparse.ArgumentTypeError("expected HOST:PORT, got %r" % text)
    return host, int(port)


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
    at the same address. A restarted bridge knows the guest's address from --guest-ip (its TARGET_IP), and learns the
    rest again from its next ARP or UDP packet.
    """

    def __init__(self, args):
        self.args = args
        self.socket = None
        # The guest's end (MAC, IP, UDP port), and the debugger as the guest addresses it (IP, UDP port).
        self.guest_mac = self.guest_ip = self.guest_port = None
        self.host_ip = self.host_port = None
        self.ip_id = 0
        self.dhcp_logged = False
        self.corrupted = DropCounter("damaged frame from the guest")

        if args.guest_ip:
            self.guest_ip = socket.inet_aton(args.guest_ip)
        # With --guest-port, replies can go out before the guest has sent anything.
        self.guest_port = args.guest_port
        if args.debugger is not None:
            # The guest's HOST_IP and HOST_PORT are the debugger's address, until it says otherwise.
            try:
                self.host_ip = socket.inet_aton(socket.gethostbyname(args.debugger[0]))
            except OSError:
                pass
            self.host_port = args.debugger[1]
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
        target = " to %s:%d" % self.args.debugger if self.args.debugger else ""
        log("forwarding KDNET traffic from udp port %d%s" % (port, target))

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
        if self.args.guest_port is not None and source_port != self.args.guest_port:
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
        # Only the guest's KDNET address is answered, so that other hosts' ARP doesn't change where replies go.
        if self.guest_ip is not None and sender_ip != self.guest_ip:
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


def run(args):
    key = follow_key()
    console = Console(key, resolve_domain(args.domain, key))
    proxy = UdpProxy(args)
    link = GuestLink(args)

    def send_to_guest(frame):
        if args.verbose:
            log("proxy > guest: %s" % describe_frame(frame))
        link.send(frame)

    try:
        while True:
            # The domain check runs commands, which stall polling for milliseconds: put it off while frames flow. A
            # domain going away meanwhile still shows, as its console pty closes.
            if not link.busy() and console.poll():
                # KDNET's MAC follows from the domain's UUID (which xl changes when it recreates a domain without a
                # fixed one), so a restarted bridge can reach the guest right away.
                smbios_uuid = read_domain(console.domid, "vm")
                if smbios_uuid and UUID_FORMAT.match(smbios_uuid):
                    proxy.guest_mac = kdnet_mac(smbios_uuid)
                    log(
                        "guest MAC is %s (from domain UUID %s)"
                        % (format_mac(proxy.guest_mac), smbios_uuid)
                    )
            link.follow(console)

            readers = [fd for fd in (proxy.socket, console.fd) if fd is not None]
            timeout = link.timeout(console.time_to_poll())
            # With --fast, the bookkeeping above costs about as much as a poll: only redo it every SPIN_SLICE, or once
            # the console was read, which may close it, or attach to or detach from the rings.
            spin_until = time.monotonic() + SPIN_SLICE if timeout == 0 else 0.0
            while True:
                readable = select.select(readers, [], [], timeout)[0]
                console_read = console.fd in readable
                if console_read:
                    link.console(console, console.read_lines())

                for frame in link.poll():
                    if args.verbose:
                        log("guest > proxy: %s" % describe_frame(frame))
                    for reply in proxy.from_guest(frame):
                        send_to_guest(reply)

                if proxy.socket in readable:
                    frame = proxy.from_debugger()
                    # Keep draining the socket while the guest is away, just don't pass anything on.
                    if frame is not None and link.attached:
                        send_to_guest(frame)

                if console_read or time.monotonic() >= spin_until:
                    break
    finally:
        link.close()


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
        "-g",
        "--guest-ip",
        default="169.254.0.2",
        help="the guest's TARGET_IP, as set by Enable-XenKd.ps1 -TargetIp"
        " (default: %(default)s; '' to learn it from the guest's first packet)",
    )
    parser.add_argument(
        "--guest-port",
        type=int,
        metavar="PORT",
        help="only forward UDP from this guest port, which KDNET uses on both ends"
        " (default: any, learned from the guest's first packet)",
    )
    parser.add_argument(
        "-p",
        "--local-port",
        type=int,
        metavar="PORT",
        help="the dom0 UDP port to talk to the debugger from (default: the"
        " debugger's port). It stays the same across restarts of the bridge, so that"
        " the debugger keeps seeing the target at the same address",
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
        help="log every frame passed in either direction, and the guest's other"
        " console output",
    )
    args = parser.parse_args()

    # Exit through the finally clauses, which tell the guest we're gone.
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    try:
        run(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
