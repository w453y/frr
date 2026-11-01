#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sbfd_initiator_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test how an S-BFD initiator handles what a reflector answers.

r1 runs an initiator towards r2, where a scripted reflector answers as
each test sets it. Against RFC 7880, Section 7.3, and RFC 5880, Sections
6.8.3 and 6.8.7:

- while Down the initiator sends once a second; once Up it announces its
  configured Desired Min TX and sends at that rate;
- the next packet after the reflector's Poll carries the Final;
- it sends no faster than the reflector's Required Min RX;
- the reflector's AdminDown takes it down, with the diagnostic saying so,
  and back to sending once a second;
- answers with the Demand bit, or a state other than Up and AdminDown,
  are discarded.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

DISCR = 999
# Jitter sends 75% to 100% of the interval apart (RFC 5880, Section 6.8.7).
SLOW_GAP_MS = 700
FAST_GAP_MS = 400


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def _modefile(r2):
    return os.path.join(r2.gearlogdir, "sbfd_mode")


def _mode(mode):
    r2 = get_topogen().gears["r2"]
    with open(_modefile(r2), "w") as f:
        f.write(mode)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BFD, None)],
        )

    tgen.start_router()

    r2 = tgen.gears["r2"]
    _mode("off")
    pid_file = os.path.join(r2.gearlogdir, "sbfd_responder.pid")
    r2.run(
        "python3 {} r2-eth0 {} {} </dev/null >/dev/null 2>&1 & echo $! > {}".format(
            os.path.join(CWD, "sbfd_responder.py"), DISCR, _modefile(r2), pid_file
        )
    )


def teardown_module(_mod):
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    pid_file = os.path.join(r2.gearlogdir, "sbfd_responder.pid")
    if os.path.exists(pid_file):
        with open(pid_file) as f:
            r2.run("kill {}".format(f.read().strip()))
    tgen.stop_topology()


def _session():
    r1 = get_topogen().gears["r1"]
    for peer in r1.vtysh_cmd("show bfd peers json", isjson=True):
        if peer.get("bfd-name") == "r2":
            return peer["status"], peer["diagnostic"]
    return None


def _expect(status, diagnostic=None):
    def _check():
        got = _session()
        if got is None or got[0] != status:
            return got
        if diagnostic is not None and got[1] != diagnostic:
            return got
        return True

    _, result = topotest.run_and_expect(_check, True, count=30, wait=0.5)
    assert result is True, "initiator is {}, expected {} {}".format(
        result, status, diagnostic or ""
    )


def _capture(seconds):
    "r1's packets to the reflector during the given time."
    r1 = get_topogen().gears["r1"]
    out = r1.run(
        "python3 {} r1-eth0 2001::10 {}".format(
            os.path.join(CWD, "sbfd_capture.py"), seconds
        )
    )
    return json.loads(out.strip().splitlines()[-1])


def _mean_gap_ms(pkts):
    assert len(pkts) >= 2, "{} packets captured".format(len(pkts))
    return 1000 * (pkts[-1]["t"] - pkts[0]["t"]) / (len(pkts) - 1)


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _up():
    "Each test below starts from an Up session."
    _mode("up")
    _expect("up")


def test_down_sends_slowly():
    "With no answer the initiator stays Down and sends once a second."
    _skip_on_failure()
    # Until r2's address is usable, the kernel holds r1's packets for
    # neighbor discovery and sends them in a burst.
    r1 = get_topogen().gears["r1"]
    _, result = topotest.run_and_expect(
        lambda: "1 received" in r1.run("ping -6 -c 1 -W 1 2001::20"),
        True,
        count=20,
        wait=0.5,
    )
    assert result, "r2 unreachable"
    _expect("down")
    pkts = _capture(4)
    assert all(p["state"] == 1 for p in pkts), pkts
    assert all(p["desired_tx"] == 1000000 for p in pkts), pkts
    gap = _mean_gap_ms(pkts)
    assert gap >= SLOW_GAP_MS, "Down, packets {:.0f} ms apart".format(gap)


def test_up_announces_configured_timers():
    "Up, the initiator announces and uses its configured interval."
    _skip_on_failure()
    _up()
    time.sleep(2)
    pkts = _capture(3)
    assert all(p["state"] == 3 for p in pkts), pkts
    assert all(p["desired_tx"] == 300000 for p in pkts), pkts
    gap = _mean_gap_ms(pkts)
    assert gap <= FAST_GAP_MS, "Up, packets {:.0f} ms apart".format(gap)


def test_poll_gets_final():
    "The packets after the reflector's Poll carry the Final, at the usual rate."
    _skip_on_failure()
    _up()
    _mode("poll")
    time.sleep(1)
    pkts = _capture(3)
    _mode("up")
    assert pkts and all(p["flags"] & 0x10 for p in pkts), pkts
    gap = _mean_gap_ms(pkts)
    assert gap >= 200, "Finals {:.0f} ms apart".format(gap)


def test_reflector_required_min_rx():
    "The initiator sends no faster than the reflector asks."
    _skip_on_failure()
    _up()
    _mode("slow")
    time.sleep(2)
    pkts = _capture(4)
    gap = _mean_gap_ms(pkts)
    assert gap >= SLOW_GAP_MS, "reflector asks 1 s, packets {:.0f} ms apart".format(gap)
    _expect("up")

    _mode("up")
    time.sleep(2)
    gap = _mean_gap_ms(_capture(3))
    assert gap <= FAST_GAP_MS, "reflector asks 100 ms, packets {:.0f} ms apart".format(
        gap
    )


def test_admin_down():
    "The reflector's AdminDown takes the initiator down and slows it."
    _skip_on_failure()
    _up()
    _mode("admindown")
    _expect("down", "neighbor signaled session down")
    gap = _mean_gap_ms(_capture(4))
    assert gap >= SLOW_GAP_MS, "AdminDown, packets {:.0f} ms apart".format(gap)


@pytest.mark.parametrize("mode", ["demand", "down"])
def test_answer_discarded(mode):
    "Answers with the Demand bit or the Down state do not keep it up."
    _skip_on_failure()
    _up()
    _mode(mode)
    _expect("down")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
