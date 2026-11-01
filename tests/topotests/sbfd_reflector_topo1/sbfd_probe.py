#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# sbfd_probe.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Send one S-BFD control packet to a reflector and print its answer, if any,
as JSON (null when none comes within a second).

sbfd_probe.py IFACE SRC DST SPORT [field=value ...]

Fields: my_discr, your_discr, mult, flags, desired_tx, auth (1 appends a
simple password section and sets the A bit).
"""

import json
import sys
import time

from scapy.all import IP, IPv6, UDP, Raw, AsyncSniffer, conf, send

conf.verb = 0

iface, src, dst, sport = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
f = {
    "my_discr": 777,
    "your_discr": 456,
    "mult": 3,
    "flags": 0xC2,  # Up, Demand
    "desired_tx": 300000,
    "auth": 0,
}
for arg in sys.argv[5:]:
    k, v = arg.split("=")
    f[k] = int(v, 0)

pkt = bytearray(24)
pkt[0] = 1 << 5
pkt[1] = f["flags"]
pkt[2] = f["mult"]
pkt[4:8] = f["my_discr"].to_bytes(4, "big")
pkt[8:12] = f["your_discr"].to_bytes(4, "big")
pkt[12:16] = f["desired_tx"].to_bytes(4, "big")
pkt[16:20] = (0).to_bytes(4, "big")
if f["auth"]:
    pkt[1] |= 0x04
    pkt += bytes([1, 7, 1]) + b"pass"
pkt[3] = len(pkt)

l3 = IPv6(src=src, dst=dst, hlim=255) if ":" in dst else IP(src=src, dst=dst, ttl=255)
# Not our own packet, which carries port 7784 too when probing with it.
sniffer = AsyncSniffer(
    iface=iface,
    filter="udp and src port 7784 and dst port %d and not src host %s" % (sport, src),
)
sniffer.start()
time.sleep(0.3)
send(l3 / UDP(sport=sport, dport=7784) / Raw(bytes(pkt)))
time.sleep(1.0)
got = sniffer.stop()

out = None
if got:
    r = got[0]
    ip = r[IPv6] if IPv6 in r else r[IP]
    b = bytes(r[UDP].payload)
    out = {
        "src": ip.src,
        "dst": ip.dst,
        "ttl": ip.hlim if IPv6 in r else ip.ttl,
        "sport": r[UDP].sport,
        "dport": r[UDP].dport,
        "vers_diag": b[0],
        "flags": b[1],
        "mult": b[2],
        "len": b[3],
        "my_discr": int.from_bytes(b[4:8], "big"),
        "your_discr": int.from_bytes(b[8:12], "big"),
        "desired_tx": int.from_bytes(b[12:16], "big"),
        "required_rx": int.from_bytes(b[16:20], "big"),
        "required_echo_rx": int.from_bytes(b[20:24], "big"),
    }
print(json.dumps(out))
