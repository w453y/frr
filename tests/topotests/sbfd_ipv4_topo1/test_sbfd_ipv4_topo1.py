#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sbfd_ipv4_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test S-BFD over IPv4 (RFC 7881), next to IPv6.

r1 runs single hop and multihop S-BFD initiators towards r2 over IPv4
and IPv6; r2 reflects them. Every session comes up, goes down while r2's
interface is shut, and comes back up.
"""

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


def _states(router):
    "Each initiator's state and remote discriminator, by name."
    return {
        peer["bfd-name"]: (peer["status"], peer["remote-id"])
        for peer in router.vtysh_cmd("show bfd peers json", isjson=True)
        if peer.get("bfd-name") in SESSIONS
    }


def _expect(router, status):
    want = {name: (status, 456) for name in SESSIONS}
    _, result = topotest.run_and_expect(
        lambda: _states(router), want, count=30, wait=0.5
    )
    assert result == want, "initiators are {}, expected {}".format(result, want)


def test_sessions_up():
    "IPv4 and IPv6 initiators come up against the reflector."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _expect(tgen.gears["r1"], "up")


def test_reflector_unreachable():
    "With r2's interface shut every initiator goes down, then up again."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    r2.vtysh_cmd("configure terminal\ninterface r2-eth0\nshutdown")
    _expect(r1, "down")
    r2.vtysh_cmd("configure terminal\ninterface r2-eth0\nno shutdown")
    _expect(r1, "up")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
