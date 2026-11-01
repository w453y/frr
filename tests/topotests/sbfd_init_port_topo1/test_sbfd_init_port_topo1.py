#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sbfd_init_port_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test the UDP source port of S-BFD initiators (RFC 7881, Section 2).

Each initiator sends all its packets from one port, held by no other
initiator and never 7784, and gets the reflected packets back there. r1
runs single hop and multihop initiators over IPv4 and IPv6 towards r2's
reflector.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

SESSIONS = ("v4", "v4-mhop", "v6", "v6-mhop")


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


def _sessions(router):
    "Each initiator's state and local discriminator, by name."
    return {
        peer["bfd-name"]: (peer["status"], peer["id"])
        for peer in router.vtysh_cmd("show bfd peers json", isjson=True)
        if peer.get("bfd-name") in SESSIONS
    }


def test_own_port():
    "Every initiator comes up, sending from a port of its own."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _all_up():
        s = _sessions(r1)
        return len(s) == len(SESSIONS) and all(v[0] == "up" for v in s.values())

    _, result = topotest.run_and_expect(_all_up, True, count=30, wait=0.5)
    assert result, "initiators: {}".format(_sessions(r1))

    out = r1.run("python3 {} r1-eth0 3".format(os.path.join(CWD, "sbfd_ports.py")))
    ports = json.loads(out.strip().splitlines()[-1])
    discrs = {str(v[1]): name for name, v in _sessions(r1).items()}

    used = {}
    for discr, name in discrs.items():
        got = ports.get(discr)
        assert got and len(got) == 1, "{} sent from ports {}".format(name, got)
        assert got[0] not in (7784, 3784, 4784), "{} sent from port {}".format(
            name, got[0]
        )
        used[name] = got[0]
    assert len(set(used.values())) == len(used), "ports shared: {}".format(used)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
