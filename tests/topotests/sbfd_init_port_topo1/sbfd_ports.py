#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# sbfd_ports.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Print, as JSON, the UDP source ports each S-BFD initiator on IFACE sent its
packets to port 7784 from during SECONDS, keyed by its My Discriminator.

sbfd_ports.py IFACE SECONDS
"""

import json
import sys

from scapy.all import IP, IPv6, UDP, sniff

iface, secs = sys.argv[1], float(sys.argv[2])
ports = {}
for p in sniff(iface=iface, filter="udp dst port 7784", timeout=secs):
    b = bytes(p[UDP].payload)
    if len(b) < 24 or not (IP in p or IPv6 in p):
        continue
    my_discr = str(int.from_bytes(b[4:8], "big"))
    ports.setdefault(my_discr, set()).add(p[UDP].sport)
print(json.dumps({k: sorted(v) for k, v in ports.items()}))
