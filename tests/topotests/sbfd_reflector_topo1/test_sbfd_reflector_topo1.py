#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sbfd_reflector_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test what an S-BFD reflector answers, and what it does not.

r1 sends crafted S-BFD control packets to r2's reflector over IPv4 and
IPv6, to r2's first address and to a second one, and checks the answer
against RFC 7880, Section 7.2, and RFC 7881, Section 6:

- the reply comes from the address the packet was sent to, with TTL 255,
  from port 7784 to the packet's source port;
- state Up, Demand clear, Final for a Poll, diagnostic zero;
- Detect Mult and Desired Min TX as received, the discriminators swapped,
  a non-zero Required Min RX and a zero Required Min Echo RX;
- no answer to a packet that is not valid, comes from port 7784, lacks
  the Demand bit or names an unknown discriminator.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

PROBE = os.path.join(CWD, "sbfd_probe.py")
# r2's addresses, and r1's source towards each.
TARGETS = {
    "v4": ("10.0.1.20", "10.0.1.10"),
    "v4-second": ("10.0.1.21", "10.0.1.10"),
    "v6": ("2001::20", "2001::10"),
    "v6-second": ("2001::21", "2001::10"),
}


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BFD, None)],
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _probe(target, sport=50000, **fields):
    "r2's answer to one packet from r1, or None."
    r1 = get_topogen().gears["r1"]
    dst, src = TARGETS[target]
    args = " ".join("{}={}".format(k, v) for k, v in fields.items())
    out = r1.run("python3 {} r1-eth0 {} {} {} {}".format(PROBE, src, dst, sport, args))
    return json.loads(out.strip().splitlines()[-1])


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_reply(target):
    "The reply's addresses, ports and fields."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reply = _probe(target, sport=50001, mult=4, desired_tx=250000)
    assert reply is not None, "no reply from {}".format(TARGETS[target][0])
    want = {
        "src": TARGETS[target][0],
        "dst": TARGETS[target][1],
        "ttl": 255,
        "sport": 7784,
        "dport": 50001,
        "vers_diag": 0x20,
        "flags": 0xC0,
        "mult": 4,
        "len": 24,
        "my_discr": 456,
        "your_discr": 777,
        "desired_tx": 250000,
        "required_echo_rx": 0,
    }
    got = {k: reply[k] for k in want}
    assert got == want, "reply from {}: {}".format(TARGETS[target][0], reply)
    assert reply["required_rx"] > 0, "zero Required Min RX: {}".format(reply)


@pytest.mark.parametrize("target", ["v4", "v6"])
def test_poll_gets_final(target):
    "A Poll is answered with a Final."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reply = _probe(target, sport=50002, flags=0xE2)
    assert reply is not None, "no reply to a Poll"
    assert reply["flags"] == 0xD0, "reply to a Poll: {}".format(reply)


DROPPED = {
    "source-port-7784": {"sport": 7784},
    "demand-clear": {"flags": 0xC0},
    "unknown-discriminator": {"your_discr": 4242},
    "my-discriminator-zero": {"my_discr": 0},
    "detect-mult-zero": {"mult": 0},
    "multipoint": {"flags": 0xC3},
    "authentication": {"auth": 1},
}


@pytest.mark.parametrize("target", ["v4", "v6"])
@pytest.mark.parametrize("case", sorted(DROPPED))
def test_not_answered(target, case):
    "Packets a reflector has to discard get no answer."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    fields = dict(DROPPED[case])
    sport = fields.pop("sport", 50003)
    reply = _probe(target, sport=sport, **fields)
    assert reply is None, "{}: answered with {}".format(case, reply)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
