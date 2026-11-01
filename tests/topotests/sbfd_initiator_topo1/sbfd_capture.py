#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# sbfd_capture.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Print, as JSON, the S-BFD control packets SRC sends to port 7784 on IFACE
during SECONDS: time, state, flags and Desired Min TX of each.

sbfd_capture.py IFACE SRC SECONDS
"""

import json
import sys

from scapy.all import UDP, sniff

iface, src, secs = sys.argv[1], sys.argv[2], float(sys.argv[3])
out = []
for p in sniff(
    iface=iface, filter="udp dst port 7784 and src host %s" % src, timeout=secs
):
    b = bytes(p[UDP].payload)
    if len(b) < 24:
        continue
    out.append(
        {
            "t": float(p.time),
            "state": b[1] >> 6,
            "flags": b[1],
            "desired_tx": int.from_bytes(b[12:16], "big"),
        }
    )
print(json.dumps(out))
