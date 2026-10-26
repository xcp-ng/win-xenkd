#!/usr/bin/env python3
"""Tests for xenkd-bridge.py's shared rings, without a guest: a fake xenkd (following xenkd/xenkd.c) works on a
bytearray that stands in for guest memory.

Run with `python3 test_xenkd_bridge.py` from anywhere.
"""

import importlib.util
import os
import random
import struct
import sys
import types
import unittest
from unittest import mock

# The bridge only runs in dom0, but its ring code doesn't need tty, so the tests also run elsewhere.
try:
    import tty  # noqa: F401
except ImportError:
    sys.modules["tty"] = types.ModuleType("tty")

spec = importlib.util.spec_from_file_location(
    "xenkd_bridge",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "xenkd-bridge.py"),
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

PAGE_SIZE = bridge.PAGE_SIZE
SLOT_SIZE = 2048
TX_SLOTS = 32
RX_SLOTS = 16
PAGES = 1 + (TX_SLOTS + RX_SLOTS) * SLOT_SIZE // PAGE_SIZE
TX_OFFSET = PAGE_SIZE
RX_OFFSET = PAGE_SIZE + TX_SLOTS * SLOT_SIZE
BASE_GFN = 0x1000
DOMID = "7"


class FakeGuest:
    """xenkd's end of the shared area, in memory whose pages are guest frames BASE_GFN onwards."""

    def __init__(self, generation=0x1234):
        self.memory = bytearray((PAGES + 2) * PAGE_SIZE)
        # The area starts a page in, as it would inside XENKD_ADAPTER.
        self.area = memoryview(self.memory)[PAGE_SIZE : (PAGES + 1) * PAGE_SIZE]
        self.words = self.area.cast("I")
        self.initialize(generation)

    def get(self, offset):
        return self.words[offset // 4]

    def set(self, offset, value):
        self.words[offset // 4] = value & 0xFFFFFFFF

    def initialize(self, generation):
        """XenKdInitializeShm."""
        self.set(bridge.SHM_MAGIC_OFFSET, 0)
        self.area[0:PAGE_SIZE] = bytes(PAGE_SIZE)
        struct.pack_into(
            "<6I", self.area, 4, 1, 0, PAGES, SLOT_SIZE, TX_SLOTS, RX_SLOTS
        )
        for index in range(PAGES):
            struct.pack_into(
                "<Q", self.area, bridge.SHM_GFN_OFFSET + 8 * index, BASE_GFN + 1 + index
            )
        self.generation = generation
        self.set(bridge.SHM_GENERATION_OFFSET, generation)
        self.set(bridge.SHM_MAGIC_OFFSET, bridge.SHM_MAGIC)

    def shutdown(self):
        self.set(bridge.SHM_MAGIC_OFFSET, 0)
        self.set(bridge.SHM_GENERATION_OFFSET, 0)

    def announce(self):
        return b"xenkd-shm v1 gfn=%x gen=%x" % (BASE_GFN + 1, self.generation)

    @property
    def attached(self):
        return self.get(bridge.SHM_DOM0_GENERATION) == self.generation

    def send(self, frame):
        """XenKdSendFrame, without the wait: False if the TX ring is full."""
        prod = self.get(bridge.SHM_TX_PROD)
        if (prod - self.get(bridge.SHM_TX_CONS)) & 0xFFFFFFFF >= TX_SLOTS:
            return False
        offset = TX_OFFSET + (prod % TX_SLOTS) * SLOT_SIZE
        self.set(offset, len(frame))
        self.area[offset + 4 : offset + 4 + len(frame)] = frame
        self.set(bridge.SHM_TX_PROD, prod + 1)
        return True

    def receive(self):
        """XenKdReceiveFrame: the next frame, or None."""
        cons = self.get(bridge.SHM_RX_CONS)
        if cons == self.get(bridge.SHM_RX_PROD):
            return None
        offset = RX_OFFSET + (cons % RX_SLOTS) * SLOT_SIZE
        frame = bytes(self.area[offset + 4 : offset + 4 + self.get(offset)])
        self.set(bridge.SHM_RX_CONS, cons + 1)
        return frame


class FakeMemory:
    """ForeignMemory over a FakeGuest."""

    def __init__(self, guest):
        self.guest = guest
        self.mapped = 0
        self.closed = False

    def map(self, domid, gfns):
        assert domid == DOMID
        first = gfns[0] - BASE_GFN
        if gfns != list(range(gfns[0], gfns[0] + len(gfns))) or first < 0:
            raise OSError(14, "only contiguous frames in this fake")
        if first + len(gfns) > len(self.guest.memory) // PAGE_SIZE:
            raise OSError(14, "cannot map gfn %x" % gfns[-1])
        self.mapped += 1
        view = memoryview(self.guest.memory)[
            first * PAGE_SIZE : (first + len(gfns)) * PAGE_SIZE
        ]
        return object(), view

    def unmap(self, address, pages):
        self.mapped -= 1

    def close(self):
        self.closed = True


class FakeConsole:
    domid = DOMID
    fd = 3


def frame(number, length=100):
    return bytes([number & 0xFF]) * length


class SharedRingsTest(unittest.TestCase):
    def setUp(self):
        self.guest = FakeGuest()
        self.memory = FakeMemory(self.guest)
        self.link = bridge.GuestLink(
            types.SimpleNamespace(verbose=False, fast=False), self.memory
        )

    def attach(self):
        self.link.console(FakeConsole(), [b"", b"boot noise", self.guest.announce()])
        self.assertTrue(self.link.attached)
        self.assertTrue(self.guest.attached)

    def test_attach(self):
        # Frames from before dom0 attached are stale: dropped.
        self.guest.set(bridge.SHM_TX_PROD, 5)
        self.guest.set(bridge.SHM_RX_CONS, 9)
        self.attach()
        self.assertEqual(self.guest.get(bridge.SHM_TX_CONS), 5)
        self.assertEqual(self.guest.get(bridge.SHM_RX_PROD), 9)
        self.assertEqual(self.link.poll(), [])
        # Only the area stays mapped.
        self.assertEqual(self.memory.mapped, 1)

    def test_poll_timeout(self):
        self.assertFalse(self.link.busy())
        self.assertEqual(self.link.timeout(1.0), 1.0)
        self.attach()
        # Fast while frames flow, spinning with --fast. The domain check waits, so its overdue deadline doesn't count.
        self.assertTrue(self.link.busy())
        self.assertEqual(self.link.timeout(0.0), bridge.ACTIVE_POLL_INTERVAL)
        self.link.args.fast = True
        self.assertEqual(self.link.timeout(1.0), 0.0)
        # Slower once they stop.
        self.link.last_traffic -= bridge.ACTIVE_PERIOD
        self.assertFalse(self.link.busy())
        self.assertEqual(self.link.timeout(1.0), bridge.IDLE_POLL_INTERVAL)
        self.link.args.fast = False
        self.assertEqual(self.link.timeout(1.0), bridge.IDLE_POLL_INTERVAL)
        self.assertEqual(self.link.timeout(0.001), 0.001)
        # A frame makes polling fast again.
        self.guest.send(frame(1))
        self.link.poll()
        self.assertTrue(self.link.busy())
        self.assertEqual(self.link.timeout(1.0), bridge.ACTIVE_POLL_INTERVAL)

    def test_empty_slots(self):
        # Frames of length 0 are skipped, but still consumed.
        self.attach()
        self.guest.send(b"")
        self.guest.send(b"")
        self.assertEqual(self.link.poll(), [])
        self.assertEqual(
            self.guest.get(bridge.SHM_TX_CONS), self.guest.get(bridge.SHM_TX_PROD)
        )
        self.guest.send(frame(1))
        self.assertEqual(self.link.poll(), [frame(1)])

    def test_heartbeat(self):
        self.attach()
        before = self.guest.get(bridge.SHM_DOM0_HEARTBEAT)
        self.link.poll()
        self.link.poll()
        self.assertEqual(
            self.guest.get(bridge.SHM_DOM0_HEARTBEAT), (before + 2) & 0xFFFFFFFF
        )

    def test_announce_while_attached(self):
        self.attach()
        self.guest.send(frame(1))
        self.link.console(FakeConsole(), [self.guest.announce()])
        # Same generation: the rings aren't reset.
        self.assertEqual(self.link.poll(), [frame(1)])

    def test_stale_announce(self):
        self.link.console(
            FakeConsole(), [b"xenkd-shm v1 gfn=%x gen=99" % (BASE_GFN + 1)]
        )
        self.assertFalse(self.link.attached)
        self.assertEqual(self.memory.mapped, 0)

    def test_bad_geometry(self):
        self.guest.set(0x010, 1000)  # SlotSize
        self.link.console(FakeConsole(), [self.guest.announce()])
        self.assertFalse(self.link.attached)
        self.assertEqual(self.memory.mapped, 0)

    def test_frames_both_ways(self):
        self.attach()
        # Several times around both rings.
        for number in range(100):
            self.assertTrue(self.guest.send(frame(number, 60 + number)))
            self.assertTrue(self.guest.send(frame(number + 1, bridge.MAX_FRAME)))
            self.assertEqual(
                self.link.poll(),
                [frame(number, 60 + number), frame(number + 1, bridge.MAX_FRAME)],
            )
            self.link.send(frame(number, 42 + number))
            self.assertEqual(self.guest.receive(), frame(number, 42 + number))
            self.assertIsNone(self.guest.receive())

    def test_tx_ring_full(self):
        self.attach()
        sent = 0
        while self.guest.send(frame(sent)):
            sent += 1
        self.assertEqual(sent, TX_SLOTS)
        self.assertEqual(
            self.link.poll(), [frame(number) for number in range(TX_SLOTS)]
        )
        self.assertTrue(self.guest.send(frame(0)))

    def test_rx_ring_full(self):
        self.attach()
        for number in range(RX_SLOTS + 3):
            self.link.send(frame(number))
        self.assertEqual(self.link.full.count, 3)
        self.assertEqual(
            [self.guest.receive() for _ in range(RX_SLOTS)],
            [frame(n) for n in range(RX_SLOTS)],
        )
        self.assertIsNone(self.guest.receive())
        self.link.send(frame(1))
        self.assertEqual(self.guest.receive(), frame(1))

    def test_frame_too_large(self):
        self.attach()
        self.link.send(frame(1, bridge.MAX_FRAME + 1))
        self.assertEqual(self.link.too_large.count, 1)
        self.assertIsNone(self.guest.receive())
        self.assertTrue(self.link.attached)

    def test_generation_change(self):
        self.attach()
        self.guest.initialize(0x5678)
        self.guest.send(frame(1))
        self.assertEqual(self.link.poll(), [])
        self.assertFalse(self.link.attached)
        self.assertEqual(self.memory.mapped, 0)
        # The new generation's announce attaches again.
        self.attach()

    def test_guest_shutdown(self):
        self.attach()
        self.guest.shutdown()
        self.link.send(frame(1))
        self.assertFalse(self.link.attached)
        self.assertIsNone(self.guest.receive())

    def test_bad_length(self):
        self.attach()
        self.guest.send(frame(1))
        self.guest.set(TX_OFFSET, bridge.MAX_FRAME + 1)
        self.assertEqual(self.link.poll(), [])
        self.assertFalse(self.link.attached)
        # It tells the guest, which announces again.
        self.assertFalse(self.guest.attached)

    def test_bad_indices(self):
        self.attach()
        self.guest.set(
            bridge.SHM_TX_PROD, self.guest.get(bridge.SHM_TX_PROD) + TX_SLOTS + 1
        )
        self.assertEqual(self.link.poll(), [])
        self.assertFalse(self.link.attached)

        self.attach()
        self.guest.set(bridge.SHM_RX_CONS, self.guest.get(bridge.SHM_RX_CONS) + 1)
        self.link.send(frame(1))
        self.assertFalse(self.link.attached)

    def test_domain_gone(self):
        self.attach()
        console = FakeConsole()
        console.fd = None
        self.link.follow(console)
        self.assertFalse(self.link.attached)
        self.assertFalse(self.guest.attached)

    def test_close(self):
        self.attach()
        self.link.close()
        self.assertFalse(self.guest.attached)
        self.assertEqual(self.memory.mapped, 0)
        self.assertTrue(self.memory.closed)


class FakeXenstore:
    """xenstore-list and xenstore-read over a dict of paths, standing in for bridge.query."""

    def __init__(self):
        self.entries = {"/local/domain/0/name": "Domain-0"}

    def add_domain(self, domid, smbios_uuid, name):
        base = "/local/domain/%d" % domid
        self.entries[base + "/vm"] = "/vm/%s" % smbios_uuid
        self.entries[base + "/name"] = name
        self.entries[base + "/console/tty"] = "/dev/pts/%d" % domid

    def remove_domain(self, domid):
        base = "/local/domain/%d/" % domid
        for path in [path for path in self.entries if path.startswith(base)]:
            del self.entries[path]

    def __call__(self, *command):
        if command[0] == "xenstore-list":
            prefix = command[1] + "/"
            children = {
                path[len(prefix) :].split("/")[0]
                for path in self.entries
                if path.startswith(prefix)
            }
            return "\n".join(sorted(children, key=int)) or None
        assert command[0] == "xenstore-read"
        # Like xenstore-read, fail if any of the paths is missing.
        if not all(path in self.entries for path in command[1:]):
            return None
        return "\n".join(self.entries[path] for path in command[1:])


UUID_A = "0b8e6a3c-1d2f-4e5a-9b7c-123456789abc"
UUID_B = "d4c3b2a1-0f9e-4d8c-8b7a-fedcba987654"
UUID_C = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9"


class DomainTest(unittest.TestCase):
    def setUp(self):
        self.xenstore = FakeXenstore()
        self.xenstore.add_domain(3, UUID_A, "win11")
        self.xenstore.add_domain(4, UUID_B, "linux")
        patch = mock.patch.object(bridge, "query", self.xenstore)
        patch.start()
        self.addCleanup(patch.stop)

    def test_resolve_xapi(self):
        self.assertEqual(bridge.resolve_domain(str(UUID_A).upper(), "vm"), UUID_A)
        self.assertEqual(bridge.resolve_domain("4", "vm"), UUID_B)
        self.assertEqual(bridge.resolve_domain("win11", "vm"), UUID_A)
        # A UUID needn't be running.
        self.xenstore.remove_domain(3)
        self.assertEqual(bridge.resolve_domain(str(UUID_A), "vm"), UUID_A)

    def test_resolve_xl(self):
        self.assertEqual(bridge.resolve_domain(str(UUID_A), "name"), "win11")
        self.assertEqual(bridge.resolve_domain("4", "name"), "linux")
        # A name needn't be running.
        self.xenstore.remove_domain(3)
        self.assertEqual(bridge.resolve_domain("win11", "name"), "win11")

    def test_resolve_failures(self):
        self.xenstore.remove_domain(3)
        for domain, key in (
            ("3", "vm"),
            ("0", "vm"),
            ("win11", "vm"),
            ("Domain-0", "vm"),
            ("3", "name"),
            (str(UUID_A), "name"),
        ):
            with self.assertRaises(SystemExit, msg=(domain, key)):
                bridge.resolve_domain(domain, key)
        # XAPI lets names repeat.
        self.xenstore.add_domain(7, UUID_A, "linux")
        with self.assertRaises(SystemExit):
            bridge.resolve_domain("linux", "vm")

    def follow(self, key, value, rebooted_uuid):
        console = bridge.Console(key, value)
        fds = iter(range(100, 200))
        with (
            mock.patch.object(bridge.os, "open", lambda *args: next(fds)),
            mock.patch.object(bridge.os, "close"),
            mock.patch.object(bridge.os, "O_NOCTTY", 0, create=True),
            mock.patch.object(bridge.os, "O_NONBLOCK", 0, create=True),
            mock.patch.object(
                bridge, "tty", types.SimpleNamespace(setraw=lambda fd: None)
            ),
        ):
            self.assertTrue(console.poll())
            self.assertEqual((console.domid, console.path), ("3", "/dev/pts/3"))
            opened = console.fd
            # Still there: left alone.
            console.next_check = 0.0
            self.assertFalse(console.poll())
            self.assertEqual(console.fd, opened)
            # Rebooted: a new domid. The other domain is never picked.
            self.xenstore.remove_domain(3)
            self.xenstore.add_domain(9, rebooted_uuid, "win11")
            console.next_check = 0.0
            self.assertTrue(console.poll())
            self.assertEqual((console.domid, console.path), ("9", "/dev/pts/9"))
            self.assertNotEqual(console.fd, opened)
            # Gone.
            self.xenstore.remove_domain(9)
            console.next_check = 0.0
            self.assertFalse(console.poll())
            self.assertIsNone(console.fd)

    def test_follow_xapi(self):
        self.follow("vm", UUID_A, UUID_A)

    def test_follow_xl(self):
        # xl gives the recreated domain a new UUID.
        self.follow("name", "win11", UUID_C)

    def test_xapi_ignores_names(self):
        console = bridge.Console("vm", UUID_A)
        self.xenstore.remove_domain(3)
        self.xenstore.add_domain(5, UUID_C, "win11")
        self.assertFalse(console.poll())
        self.assertIsNone(console.fd)


def reference_checksum(data):
    """RFC 1071's checksum, word by word."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class ChecksumTest(unittest.TestCase):
    def assertMatchesReference(self, data):
        self.assertEqual(
            bridge.checksum(data),
            reference_checksum(data),
            "%d bytes: %s" % (len(data), data.hex()),
        )

    def test_rfc1071_example(self):
        self.assertEqual(
            bridge.checksum(bytes.fromhex("0001f203f4f5f6f7")), ~0xDDF2 & 0xFFFF
        )

    def test_edge_cases(self):
        # A sum of 0 is all zeros, a multiple of 0xFFFF sums to 0xFFFF: they differ.
        for data in (b"", b"\0", b"\0\0\0\0", b"\xff\xff", b"\xff\xff\xff\xff"):
            self.assertEqual(bridge.checksum(data), reference_checksum(data))
        self.assertEqual(bridge.checksum(b"\0\0"), 0xFFFF)
        self.assertEqual(bridge.checksum(b"\xff\xff"), 0)
        self.assertEqual(bridge.checksum(b"\x00\x01\xff\xfe"), 0)
        # Odd lengths are padded with a zero byte at the end.
        self.assertEqual(bridge.checksum(b"\x12"), ~0x1200 & 0xFFFF)

    def test_random(self):
        generator = random.Random(1071)
        for length in range(bridge.MAX_FRAME + 1):
            data = bytes(generator.getrandbits(8) for _ in range(length))
            self.assertMatchesReference(data)

    def test_zeros(self):
        for length in range(1, bridge.MAX_FRAME + 1):
            self.assertEqual(bridge.checksum(bytes(length)), 0xFFFF)

    def test_carry(self):
        # Every word but the last is 0xffff: the end-around carry decides the result.
        for length in range(1, 1025):
            self.assertMatchesReference(b"\xff" * (length - 1) + b"\x01")

    def test_stride(self):
        for length in (2, 4, 8, 16, 32, 64, 128, 256, 512):
            data = b"\x01" + bytes(length - 1)
            self.assertMatchesReference(data)
            self.assertEqual(bridge.checksum(data), ~0x0100 & 0xFFFF)

    def test_frames_verify(self):
        # What the bridge builds for the guest is what it accepts from the guest.
        proxy = bridge.UdpProxy(
            types.SimpleNamespace(
                guest_ip="169.254.0.2",
                guest_port=None,
                debugger=None,
                local_port=None,
            )
        )
        proxy.guest_mac = b"\x02" * 6
        proxy.host_ip = b"\xa9\xfe\x00\x01"
        proxy.host_port = 50000
        payload = (bytes(range(256)) * 6)[: bridge.MAX_FRAME - 42]
        for length in (0, 1, 2, 63, 1000, len(payload)):
            proxy.socket = types.SimpleNamespace(
                recvfrom=lambda size: (payload[:length], None)
            )
            frame = proxy.from_debugger()
            self.assertEqual(len(frame), 42 + length)
            self.assertEqual(bridge.checksum(frame[14:34]), 0)
            self.assertIsNone(proxy.check_udp(frame, 20, len(frame) - 34))


class FilterTest(unittest.TestCase):
    GUEST = b"\xa9\xfe\x00\x02"
    OTHER = b"\xa9\xfe\x77\x28"
    HOST = b"\xa9\xfe\x00\x01"

    def make_proxy(self, guest_ip="169.254.0.2", guest_port=None):
        proxy = bridge.UdpProxy(
            types.SimpleNamespace(
                guest_ip=guest_ip,
                guest_port=guest_port,
                debugger=None,
                local_port=None,
            )
        )
        proxy.guest_mac = b"\x02" * 6
        proxy.sent = []
        proxy.socket = types.SimpleNamespace(
            sendto=lambda data, address: proxy.sent.append(data)
        )
        return proxy

    def guest_frame(self, source_ip, payload=b"hello"):
        # The proxy's frames for the guest, with the addresses swapped, make the guest's frames for the proxy.
        builder = self.make_proxy()
        builder.host_ip, builder.host_port = source_ip, 5364
        builder.guest_ip, builder.guest_port = self.HOST, 5364
        builder.socket = types.SimpleNamespace(recvfrom=lambda size: (payload, None))
        return builder.from_debugger()

    def arp_request(self, sender_ip):
        mac = b"\x02" * 6
        return (
            b"\xff" * 6
            + mac
            + bridge.ETHERTYPE_ARP
            + struct.pack("!HHBBH", 1, 0x0800, 6, 4, bridge.ARP_REQUEST)
            + mac
            + sender_ip
            + bytes(6)
            + self.HOST
        ).ljust(60, b"\0")

    def test_forwards_the_guest(self):
        proxy = self.make_proxy()
        proxy.from_guest(self.guest_frame(self.GUEST))
        self.assertEqual(proxy.sent, [b"hello"])
        self.assertEqual((proxy.host_ip, proxy.host_port), (self.HOST, 5364))

    def test_ignores_other_hosts(self):
        proxy = self.make_proxy()
        proxy.from_guest(self.guest_frame(self.OTHER))
        self.assertEqual(proxy.sent, [])
        self.assertIsNone(proxy.host_ip)
        self.assertIsNone(proxy.guest_port)

    def test_ignores_other_arp(self):
        proxy = self.make_proxy()
        self.assertEqual(proxy.arp(self.arp_request(self.OTHER)), [])
        self.assertEqual(len(proxy.arp(self.arp_request(self.GUEST))), 1)

    def test_any_port_by_default(self):
        proxy = self.make_proxy()
        self.assertIsNone(proxy.guest_port)
        proxy.from_guest(self.guest_frame(self.GUEST))
        self.assertEqual(proxy.guest_port, 5364)

    def test_filters_by_port(self):
        proxy = self.make_proxy(guest_port=1234)
        self.assertEqual(proxy.guest_port, 1234)
        proxy.from_guest(self.guest_frame(self.GUEST))
        self.assertEqual(proxy.sent, [])
        self.assertIsNone(proxy.host_ip)
        self.assertEqual(proxy.guest_port, 1234)

        proxy = self.make_proxy(guest_port=5364)
        proxy.from_guest(self.guest_frame(self.GUEST))
        self.assertEqual(proxy.sent, [b"hello"])

    def test_learns_the_guest_without_an_address(self):
        proxy = self.make_proxy(guest_ip="")
        self.assertIsNone(proxy.guest_ip)
        proxy.from_guest(self.guest_frame(self.OTHER))
        self.assertEqual(proxy.sent, [b"hello"])
        self.assertEqual(proxy.guest_ip, self.OTHER)


if __name__ == "__main__":
    unittest.main()
