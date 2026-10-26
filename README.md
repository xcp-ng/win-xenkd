# xenkd

Fast Windows kernel debugging for Xen HVM guests, with no emulated NIC.

xenkd is a [KDNET extensibility module](https://learn.microsoft.com/windows-hardware/drivers/debugger/how-to-develop-kdnet-extensibility-modules)
(`kd_08_5853.dll`). It hands KDNET's Ethernet frames to dom0 through rings in guest memory that dom0 maps directly. A
small bridge in dom0 forwards them to WinDbg over UDP. The guest needs no network adapter for the debugger, and the
debug link doesn't depend on the guest's own Xen drivers.

It's fast:

| Transport                             | `.dump /f /k` of a 360 MB kernel range |
|---------------------------------------|----------------------------------------|
| hvm_serial                            | **Too slow, does not complete**        |
| xenkd shared rings                    | **21.2 MB/s** (17 s)                   |
| xenkd shared rings, bridge `--fast`   | **32.7 MB/s** (11 s)                   |

## How it works

```
 Guest (Windows)                         dom0                                  Debug host
┌─────────────────────────────┐        ┌──────────────────────┐              ┌──────────┐
│ kernel ── KDNET ── xenkd    │        │   xenkd-bridge.py    │     UDP      │  WinDbg  │
│                      │      │ shared │                      │◄────────────►│          │
│        TX/RX rings ◄─┴──────┼────────┼─► maps & polls       │              └──────────┘
│                             │ memory │                      │
│        PV console ──────────┼────────┼─► "xenkd-shm v1 ..." │
└─────────────────────────────┘        └──────────────────────┘
```

- **Rings.** xenkd reserves a 25-page area inside the memory KDNET gives it: a header page, a 32-slot ring from the
  guest, and a 16-slot ring to the guest, each slot holding one frame. Both sides poll, so there are no interrupts or
  event channels to set up (KDNET runs with interrupts off anyway). The layout is in
  [xenkd/xenkd_shm.h](xenkd/xenkd_shm.h).
- **Rendezvous.** While no bridge is attached, xenkd writes one line a second on the PV console:
  `xenkd-shm v1 gfn=<header frame> gen=<generation>`. The bridge reads the console, maps the header, then maps every
  page the header lists.
- **Liveness.** The bridge bumps a heartbeat on every poll. Without one for 2 s, xenkd treats the link as down (frames
  are dropped, like a NIC without a cable) and announces itself again. Every re-initialization of KDNET gets a new
  generation, so the bridge never writes into a stale area.

The console carries only that announce line, so xenconsoled's rate limit doesn't matter any more.

## Requirements

- A Xen host with a dom0 shell as root (developed on XCP-ng), with CPython 3.6 or later and `libxenforeignmemory`. The
  bridge maps guest memory through CPython's C API, so it doesn't run on PyPy.
- A 64-bit Windows HVM guest with the **xenkd PCI device** (vendor `5853`, device `C201`) attached. KDNET picks its
  extensibility module by PCI vendor ID, and xenkd checks that it was loaded for this device.
- To build: Visual Studio with the WDK.

## Building

Open [xenkd.slnx](xenkd.slnx) in Visual Studio, or:

```powershell
MSBuild.exe xenkd\xenkd.vcxproj /p:Configuration=Release /p:Platform=x64
```

This produces `xenkd\x64\Release\kd_08_5853.dll`, test-signed. Only x64 is supported.

## Setting up the guest

1. Copy `kd_08_5853.dll` and [scripts/Enable-XenKd.ps1](scripts/Enable-XenKd.ps1) into the same folder in the guest.
2. From an elevated PowerShell in that folder:

   ```powershell
   .\Enable-XenKd.ps1 -HostIp <debug host IP> -BootDebug -ComPort 1
   ```

   The script finds the xenkd device, installs the DLL into System32, keeps xencons and xenbus off the PV console, and
   points the kernel debugger at KDNET with a fixed address (`TARGET_IP=169.254.0.2`, `NO_DHCP`). Add `-WhatIf` to see
   what it would change first.
3. Reboot.

The DLL is test-signed: winload loads it only while a boot debugger is attached. `-BootDebug` sets up boot debugging
on a serial port for that purpose, while the kernel itself still goes through xenkd. Attach a debugger to that serial
port when the guest boots, and continue (`g`) at the winload break.

| Parameter     | Default        | Meaning                                                                  |
|---------------|----------------|--------------------------------------------------------------------------|
| `-HostIp`     | `169.254.0.1`  | Where WinDbg is listening                                                |
| `-Port`       | `5364`         | WinDbg's UDP port                                                        |
| `-Key`        | random         | KDNET encryption key                                                     |
| `-TargetIp`   | `169.254.0.2`  | The guest's address on the debug link (the bridge's `--guest-ip`)        |
| `-BootDebug`  |                | Also debug bootmgr/winload over serial (needed for the test-signed DLL)  |
| `-ComPort`    | `1`            | The serial port for `-BootDebug`                                         |
| `-BaudRate`   | `115200`       | The serial port for `-BootDebug`                                         |
| `-Clear`      |                | Turn debugging off and remove the BCD settings                           |
| `-ClearAll`   |                | Also remove the DLL and give xencons and xenbus the console back         |

## Running the bridge

Copy [scripts/xenkd-bridge.py](scripts/xenkd-bridge.py) to dom0 (with LF line endings) and start it:

```sh
./xenkd-bridge.py <domain UUID, name or domid>
```

The bridge follows the domain across reboots, which change its domid:

- **with XAPI** (XenServer, XCP-ng, detected by `/etc/xensource-inventory`), by its UUID, since names can repeat;
- **with xl**, by its name, since `xl create` gives the domain a new UUID unless its config sets one.

Given that UUID or name, the bridge can start before the guest. Given a domid, or the other one of the two, it looks up
what to follow from the running domain.

On the debug host:

```
windbg -k net:port=5364,key=<key>
```

dom0 stands in for the network. The bridge answers the guest's ARP, sends KDNET's UDP payloads to WinDbg from an
ordinary socket, and wraps the replies back into frames. No TAP, bridge or routing is needed: WinDbg only has to reach
dom0 on one UDP port, and accept packets from it.

| Option                       | Default                    | Meaning                                                    |
|------------------------------|----------------------------|------------------------------------------------------------|
| `-d`, `--debugger HOST:PORT` | the guest's `HOST_IP:port` | Where WinDbg runs, overrides the guest's choice            |
| `-g`, `--guest-ip IP`        | `169.254.0.2`              | The guest's `-TargetIp`; `''` to learn it from its traffic |
| `--guest-port PORT`          | any                        | Only forward UDP from this guest port (`-Port`)            |
| `-p`, `--local-port PORT`    | WinDbg's port              | dom0's port; set it if WinDbg runs in dom0                 |
| `--fast`                     |                            | Poll continuously while frames flow (see Limitations)      |
| `-v`, `--verbose`            |                            | Log every frame, and the guest's other console output      |

The bridge:

- **attaches** within about a second of KDNET starting, and logs `attached to the shared area at gfn ...`;
- **survives restarts**: a new bridge reattaches within a few seconds, and the WinDbg session carries on;
- **follows reboots**: it waits for the domain to come back, whatever its new domid, then reattaches;
- **lets go cleanly** on Ctrl+C or SIGTERM, so the guest notices at once.

Don't run `xl console` on the same domain while the bridge runs: both read the same pty, and the console could swallow
the announce lines.

## Troubleshooting

- **WinDbg never connects.** In the guest, look at `HKLM\SYSTEM\CurrentControlSet\Services\kdnet` for KDNET's init
  status and xenkd's error string (`xenkd: ...`).
- **The bridge never attaches.** Run with `-v` to see whether announce lines arrive. To check that dom0 can map guest
  memory at all, run [scripts/xenkd-map-test.py](scripts/xenkd-map-test.py) `<domain>` next to the bridge. It maps the
  guest's console ring and prints its indices.
- **`guest RX ring full` drops.** These are normal in small numbers: WinDbg retransmits while the guest is busy.

## Development

- Bridge tests run anywhere, without Xen: `python scripts/test_xenkd_bridge.py`.
- [AGENTS.md](AGENTS.md) has the build checks, code constraints and the shared-area contract.

## Limitations

- x64 guests only.
- dom0 polls: every 200 µs while frames flow, every 5 ms when idle. The bridge's `--fast` polls continuously while
  frames flow instead, for about 1.5 times the throughput (see the table at the top), but keeps a dom0 CPU busy until
  1 s after the last frame.
- dom0 writes into guest memory that KDNET reserved. If Windows ever reused those pages while the bridge is attached,
  the bridge would corrupt them. The generation check makes that window small, which is acceptable for a debugging
  tool.
- Save/restore and live migration are untested.
- With `--fast`, most of each round trip is spent outside the bridge (in the guest, the network and WinDbg), so a
  faster bridge would gain little. PyPy is no help either: a PyPy build of the bridge managed only 9.0 MB/s.
