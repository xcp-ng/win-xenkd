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
│        OUT 0xEC, PFN ───────┼────────┼─► ioreq server       │
└─────────────────────────────┘        └──────────────────────┘
```

- **Rings.** xenkd reserves a 25-page area inside the memory KDNET gives it: a header page, a 32-slot ring from the
  guest, and a 16-slot ring to the guest, each slot holding one frame. Both sides poll the packet rings; the guest
  needs no interrupts or event-channel bindings. The layout is in
  [xenkd/xenkd_shm.h](xenkd/xenkd_shm.h).
- **Rendezvous.** While no bridge is attached, xenkd writes the header PFN once a second to I/O port `0xEC` using
  KDNET's `WRITE_PORT_ULONG`. The bridge registers a secondary Xen ioreq server for `0xEC–0xEF` and retains two
  mappings: the header page, and the 24 ring pages listed in its `RingGfn[]` array. The header's signature encodes
  layout version 2, which fixes the slot size and ring counts; its generation identifies the initialization.
  A `READ_PORT_ULONG` returns the accepted header PFN, or `0xFFFFFFFF` if
  detached. Without acknowledgement, xenkd starts with its link down and retries later. Writing `0xFFFFFFFF` closes
  the link: the bridge unmaps before the guest's write completes. The port identifies rendezvous protocol v1; the
  ring layout has its own version.
- **Liveness.** The bridge bumps a heartbeat on every poll. Without one for 2 s, xenkd treats the link as down (frames
  are dropped, like a NIC without a cable) and announces itself again. Every re-initialization of KDNET gets a new
  generation, so the bridge never writes into a stale area.

The PV console is not used. The bridge can run alongside `xl console`, xencons and xenbus console logging.
The default `0xEC–0xEF` range is covered by the Xen HVM DSDT's motherboard reservation. It must remain unused by
other virtual hardware. To change ports, use `Enable-XenKd.ps1 -IoPort 0x...` in the guest and `--io-port 0x...` on the
bridge. The guest option is stored as hexadecimal `XENKD_IOPORT=0x...` in BCD loadoptions. The base must be nonzero,
four-byte aligned and no greater than `0xFFFC`; reserve all four bytes in guest ACPI when choosing another range.
The version 2 header is incompatible with the earlier layout: update the guest DLL and bridge together. The I/O
register protocol and default port are unchanged.

## Requirements

- A Xen host with a dom0 shell as root (developed on XCP-ng), with CPython 3.6 or later, `libxenforeignmemory` (with
  resource mapping), `libxendevicemodel` and `libxenevtchn`. The bridge maps guest memory through CPython's C API, so
  it doesn't run on PyPy.
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

   The script finds the xenkd device, installs the DLL into System32, sets the rendezvous port, and points the kernel
   debugger at KDNET with a fixed address (`TARGET_IP=169.254.0.2`, `NO_DHCP`). Add `-WhatIf` to see what it would
   change first.
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
| `-IoPort`     | `0xEC`         | Rendezvous I/O port; must match the bridge's `--io-port`                 |
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

| Option                       | Default                    | Meaning                                                  |
|------------------------------|----------------------------|----------------------------------------------------------|
| `-d`, `--debugger HOST:PORT` | the guest's `HOST_IP:port` | Where WinDbg runs, overrides the guest's choice          |
| `--destination IP:PORT`      | `169.254.0.1:5364`         | The guest's `-HostIp` and `-Port`; ignore other traffic  |
| `--guest-ip IP`              | any                        | The guest's `-TargetIp`; ignore other guest addresses    |
| `--local-port PORT`          | WinDbg's port              | dom0's port; set it if WinDbg runs in dom0               |
| `--io-port PORT`             | `0xEC`                     | Rendezvous port; matches the guest's `-IoPort`           |
| `--fast`                     |                            | Poll continuously while frames flow (see Limitations)    |
| `-v`, `--verbose`            |                            | Log every frame                                          |

The bridge:

- **attaches** within about a second of KDNET starting, and logs `attached to the shared area at gfn ...`;
- **survives clean restarts**: a new bridge reattaches within a few seconds, and the WinDbg session carries on;
- **follows reboots**: it waits for the domain to come back, whatever its new domid, then reattaches;
- **lets go cleanly** on Ctrl+C or SIGTERM, so the guest notices at once.

On a clean exit, the bridge disables new ioreq requests, completes and notifies any pending requests, then destroys
the server. It logs `stopped ioreq server` on success; a timeout waiting for response consumption is logged separately.

For older console-based installations, `-ClearAll` still undoes the old xencons and xenbus console settings; run it
before enabling the new DLL if you want to restore the PV console. It cannot recover the previous console log level.

## Troubleshooting

- **WinDbg never connects.** In the guest, look at `HKLM\SYSTEM\CurrentControlSet\Services\kdnet` for KDNET's init
  status and xenkd's error string (`xenkd: ...`).
- **The bridge never attaches.** Check that it logs `listening on i/o port 0xec`, that the guest and bridge use the
  same port, and that both have been updated to the I/O rendezvous. To check guest-memory mapping separately, run
  [scripts/xenkd-map-test.py](scripts/xenkd-map-test.py) `<domain>` next to the bridge. It maps the guest's console ring
  and prints its indices.
- **`guest RX ring full` drops.** These are normal in small numbers: WinDbg retransmits while the guest is busy.

## Development

- Bridge tests run anywhere, without Xen: `python scripts/test_xenkd_bridge.py`.

## Limitations

- x64 guests only.
- dom0 polls: every 200 µs while frames flow, every 5 ms when idle. The bridge's `--fast` polls continuously while
  frames flow instead, for about 1.5 times the throughput (see the table at the top), but keeps a dom0 CPU busy until
  1 s after the last frame.
- dom0 writes into guest memory that KDNET reserved. If Windows ever reused those pages while the bridge is attached,
  the bridge would corrupt them. The generation check makes that window small, which is acceptable for a debugging
  tool.
- I/O rendezvous is synchronous. A hung bridge can stall the issuing guest vCPU, including in a debugger callback.
  Stop the bridge with Ctrl+C or SIGTERM so it destroys its ioreq server. SIGKILL or a process crash can leave a server
  registered in dom0; restarting the bridge is not guaranteed to recover it. Run only one bridge per guest.
- The header PFN must fit in 32 bits (below 16 TiB, excluding PFN `0xFFFFFFFF`); other ring PFNs remain 64-bit.
- Save/restore and live migration are untested.
- With `--fast`, most of each round trip is spent outside the bridge (in the guest, the network and WinDbg), so a
  faster bridge would gain little. PyPy is no help either: a PyPy build of the bridge managed only 9.0 MB/s.
