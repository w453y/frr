#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# sbfd_responder.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
A scripted S-BFD reflector for one discriminator. It answers each initiator
packet the way the file MODEFILE says, read per packet:

  up         Up, Required Min RX 100 ms
  slow       Up, Required Min RX 1 s
  poll       Up with the Poll bit
  admindown  AdminDown
  down       Down, which a reflector never sends
  demand     Up with the Demand bit, which only an initiator sets
  off        no answer

sbfd_responder.py IFACE DISCRIMINATOR MODEFILE
"""

import sys

from scapy.all import IP, IPv6, UDP, Raw, conf, send, sniff

conf.verb = 0

iface, discr, modefile = sys.argv[1], int(sys.argv[2]), sys.argv[3]


def mode():
    try:
        with open(modefile) as f:
            return f.read().strip()
    except OSError:
        return "off"


def answer(p):
    b = bytes(p[UDP].payload)
    if len(b) < 24 or int.from_bytes(b[8:12], "big") != discr:
        return
    m = mode()
    if m == "off":
        return

    r = bytearray(b[:24])
    r[0] = 1 << 5
    state = {"admindown": 0, "down": 1}.get(m, 3)
    r[1] = state << 6
    if m == "poll":
        r[1] |= 0x20
    if m == "demand":
        r[1] |= 0x02
    if b[1] & 0x20:  # Poll -> Final
        r[1] = (r[1] & ~0x20) | 0x10
    r[3] = 24
    r[4:8], r[8:12] = b[8:12], b[4:8]
    r[16:20] = (1000000 if m == "slow" else 100000).to_bytes(4, "big")
    r[20:24] = bytes(4)

    ip = p[IPv6] if IPv6 in p else p[IP]
    if IPv6 in p:
        l3 = IPv6(src=ip.dst, dst=ip.src, hlim=255)
    else:
        l3 = IP(src=ip.dst, dst=ip.src, ttl=255)
    send(l3 / UDP(sport=7784, dport=p[UDP].sport) / Raw(bytes(r)))


sniff(iface=iface, filter="udp dst port 7784", prn=answer, store=0)
