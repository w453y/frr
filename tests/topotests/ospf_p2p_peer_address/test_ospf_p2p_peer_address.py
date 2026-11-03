#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_p2p_peer_address.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
A point-to-point address with a peer is numbered unless the peer is a /32.

With "ip address 10.0.12.1 peer 10.0.12.2/30" zebra stores the local address
as a /32 and puts the /30 on the peer. zebra used to look only at the local
/32 and mark every such address unnumbered, so ospfd advertised the link with
the ifindex as Link Data and no stub link. That is how FreeBSD reports every
tunnel address (gif, gre, if_ipsec), so OSPF over those tunnels was always
unnumbered.

r1 and r2 are connected twice: r1-eth0 uses a /30 peer and must be numbered,
r1-eth1 uses a /32 peer and must stay unnumbered.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"
    for rname in ["r1", "r2"]:
        tgen.add_router(rname)

    # r1-eth0 <-> r2-eth0: peer with a /30
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-eth1 <-> r2-eth1: peer with a /32
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _address(router, ifname):
    output = json.loads(router.vtysh_cmd("show interface {} json".format(ifname)))
    for addr in output[ifname].get("ipAddresses", []):
        if addr.get("peer"):
            return addr
    return None


def _router_links(router):
    output = json.loads(
        router.vtysh_cmd("show ip ospf database router self-originate json")
    )
    links = []

    def walk(obj):
        if isinstance(obj, dict):
            if "routerLinks" in obj:
                links.extend(obj["routerLinks"].values())
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(output)
    return links


def _ifindex(router, ifname):
    output = json.loads(router.vtysh_cmd("show interface {} json".format(ifname)))
    return output[ifname]["index"]


def test_zebra_unnumbered_flag():
    "zebra marks only the /32 peer address unnumbered"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        n = rname[1]
        o = "2" if n == "1" else "1"

        addr = _address(router, "{}-eth0".format(rname))
        assert addr is not None, "{}-eth0 has no peer address".format(rname)
        assert addr["address"] == "10.0.12.{}/32".format(n)
        assert addr["peer"] == "10.0.12.{}/30".format(o)
        assert addr["unnumbered"] is False, "{}-eth0: /30 peer must be numbered".format(
            rname
        )

        addr = _address(router, "{}-eth1".format(rname))
        assert addr is not None, "{}-eth1 has no peer address".format(rname)
        assert addr["peer"] == "10.0.21.{}/32".format(o)
        assert (
            addr["unnumbered"] is True
        ), "{}-eth1: /32 peer must stay unnumbered".format(rname)


def test_ospf_interfaces():
    "ospfd sees the same unnumbered flag"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        output = json.loads(router.vtysh_cmd("show ip ospf interface json"))
        interfaces = output["interfaces"]
        assert "ifUnnumbered" not in interfaces["{}-eth0".format(rname)]
        assert interfaces["{}-eth1".format(rname)].get("ifUnnumbered") is True


def _check_router_links(router, rname):
    n = rname[1]
    o = "2" if n == "1" else "1"
    nbr = "10.255.0.{}".format(o)
    links = _router_links(router)

    expected = [
        # Numbered link: the interface address and a stub for the peer.
        {
            "linkType": "another Router (point-to-point)",
            "neighborRouterId": nbr,
            "routerInterfaceAddress": "10.0.12.{}".format(n),
        },
        {
            "linkType": "Stub Network",
            "networkAddress": "10.0.12.{}".format(o),
            "networkMask": "255.255.255.255",
        },
        # Unnumbered link: the ifindex and no stub.
        {
            "linkType": "another Router (point-to-point)",
            "neighborRouterId": nbr,
            "routerInterfaceAddress": "0.0.0.{}".format(
                _ifindex(router, "{}-eth1".format(rname))
            ),
        },
    ]
    for want in expected:
        if not any(all(link.get(k) == v for k, v in want.items()) for link in links):
            return "missing {} in {}".format(want, links)

    for link in links:
        if link.get("networkAddress", "").startswith("10.0.21."):
            return "unexpected stub for the unnumbered link: {}".format(link)

    return None


def test_ospf_router_lsa():
    "The router-LSA describes the numbered link with its address"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        test_func = partial(_check_router_links, router, rname)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: {}".format(rname, result)


def _check_routes(router, rname):
    o = "2" if rname == "r1" else "1"
    output = json.loads(router.vtysh_cmd("show ip route 10.255.0.{}/32 json".format(o)))
    routes = output.get("10.255.0.{}/32".format(o))
    if not routes:
        return "no route"

    nexthops = {
        nh.get("interfaceName"): nh
        for nh in routes[0].get("nexthops", [])
        if nh.get("active")
    }
    eth0 = nexthops.get("{}-eth0".format(rname))
    eth1 = nexthops.get("{}-eth1".format(rname))
    if not eth0 or not eth1:
        return "expected nexthops over both links: {}".format(nexthops)
    if eth0.get("ip") != "10.0.12.{}".format(o) or eth0.get("onLink"):
        return "numbered nexthop is wrong: {}".format(eth0)
    if eth1.get("ip") != "10.0.21.{}".format(o) or not eth1.get("onLink"):
        return "unnumbered nexthop must be onlink: {}".format(eth1)
    return None


def test_routes_and_ping():
    "Both links carry traffic"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        test_func = partial(_check_routes, router, rname)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: {}".format(rname, result)

    r1 = tgen.gears["r1"]
    output = r1.run("ping -c 3 -W 1 -I 10.255.0.1 10.255.0.2")
    assert " 0% packet loss" in output, output


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
