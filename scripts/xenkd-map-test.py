#!/usr/bin/env python3
"""Check that dom0 can map a guest's memory the way xenkd-bridge.py does: map the guest's PV console ring, through the
bridge's own ForeignMemory, and print its indices. Run in dom0 as root, next to xenkd-bridge.py.

    xenkd-map-test.py <domain name or domid>
"""

import importlib.util
import os
import struct
import sys

spec = importlib.util.spec_from_file_location(
    "xenkd_bridge",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "xenkd-bridge.py"),
)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

domain = sys.argv[1]
domid = domain if domain.isdigit() else bridge.query("xl", "domid", domain)
gfn = bridge.query("xenstore-read", "/local/domain/%s/console/ring-ref" % domid)
if domid is None or gfn is None:
    sys.exit("cannot find the console ring of domain %s" % domain)

memory = bridge.ForeignMemory()
address, view = memory.map(domid, [int(gfn)])
# struct xencons_interface: in[1024], out[2048], then in_cons, in_prod, out_cons, out_prod.
in_cons, in_prod, out_cons, out_prod = struct.unpack_from("<4I", view, 3072)
print(
    "domain %s, console ring at gfn %x: in %d/%d, out %d/%d"
    % (domid, int(gfn), in_cons, in_prod, out_cons, out_prod)
)
view.release()
memory.unmap(address, 1)
memory.close()
