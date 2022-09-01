# Copyright (c) ByteDance, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import random
import string
import unittest

from drgn import Object
from drgn.helpers.linux.fs import path_lookup
from drgn.helpers.linux.net import get_net_ns_by_inode, netdev_get_by_name
from drgn.helpers.linux.tc import for_each_tcf_chain, qdisc_lookup
from tests.linux_kernel import LinuxKernelTestCase

try:
    from pyroute2 import NetNS, protocols
    from pyroute2.netlink import (
        NLM_F_ACK,
        NLM_F_CREATE,
        NLM_F_EXCL,
        NLM_F_REQUEST,
        nlmsg,
    )
    from pyroute2.netlink.exceptions import NetlinkError
    from pyroute2.netlink.rtnl import RTM_NEWTFILTER, TC_H_INGRESS, TC_H_ROOT
    from pyroute2.netlink.rtnl.tcmsg import cls_u32, plugins

    have_pyroute2 = True
except ImportError:
    have_pyroute2 = False


@unittest.skipUnless(have_pyroute2, "pyroute2 not found")
class TestTc(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ns = None
        while cls.ns is None:
            try:
                cls.name = "".join(
                    random.choice(string.ascii_letters) for _ in range(16)
                )
                cls.ns = NetNS(cls.name, flags=os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                pass
        # ip link add dummy0 type dummy
        try:
            cls.ns.link("add", ifname="dummy0", kind="dummy")
        except NetlinkError:
            raise unittest.SkipTest(
                "kernel does not support dummy interface (CONFIG_DUMMY)"
            )
        cls.index = cls.ns.link_lookup(ifname="dummy0")[0]
        inode = path_lookup(
            cls.prog, os.path.realpath(f"/var/run/netns/{cls.name}")
        ).dentry.d_inode
        cls.net = get_net_ns_by_inode(inode)
        cls.netdev = netdev_get_by_name(cls.net, "dummy0")

    @classmethod
    def tearDownClass(cls):
        cls.ns.remove()
        super().tearDownClass()

    def tearDown(self):
        for parent in [TC_H_ROOT, TC_H_INGRESS]:  # delete all Qdiscs
            try:
                self.ns.tc("delete", index=self.index, parent=parent)
            except NetlinkError:
                pass

    def test_qdisc_lookup(self):
        # tc qdisc add dev dummy0 root handle 1: prio
        try:
            self.ns.tc(
                "add",
                kind="prio",
                index=self.index,
                handle="1:",
                # default TCA_OPTIONS for sch_prio, see [iproute2] tc/q_prio.c:prio_parse_opt()
                bands=3,
                priomap=[1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
            )
        except NetlinkError:
            self.skipTest(
                "kernel does not support Multi Band Priority Queueing (CONFIG_NET_SCH_PRIO)"
            )
        # tc qdisc add dev dummy0 parent 1:1 handle 10: sfq
        try:
            self.ns.tc("add", kind="sfq", index=self.index, parent="1:1", handle="10:")
        except NetlinkError:
            self.skipTest(
                "kernel does not support Stochastic Fairness Queueing (CONFIG_NET_SCH_SFQ)"
            )
        # tc qdisc add dev dummy0 parent 1:2 handle 20: tbf rate 20kbit buffer 1600 limit 3000
        try:
            self.ns.tc(
                "add",
                kind="tbf",
                index=self.index,
                parent="1:2",
                handle="20:",
                rate=2500,
                burst=1600,
                limit=3000,
            )
        except NetlinkError:
            self.skipTest(
                "kernel does not support Token Bucket Filter (CONFIG_NET_SCH_TBF)"
            )
        # tc qdisc add dev dummy0 parent 1:3 handle 30: sfq
        self.ns.tc("add", kind="sfq", index=self.index, parent="1:3", handle="30:")
        # tc qdisc add dev dummy0 ingress
        try:
            self.ns.tc("add", kind="ingress", index=self.index)
        except NetlinkError:
            self.skipTest(
                "kernel does not support ingress Qdisc (CONFIG_NET_SCH_INGRESS)"
            )

        self.assertEqual(qdisc_lookup(self.netdev, 0x1).ops.id.string_(), b"prio")
        self.assertEqual(qdisc_lookup(self.netdev, 0x10).ops.id.string_(), b"sfq")
        self.assertEqual(qdisc_lookup(self.netdev, 0x20).ops.id.string_(), b"tbf")
        self.assertEqual(qdisc_lookup(self.netdev, 0x30).ops.id.string_(), b"sfq")
        self.assertEqual(qdisc_lookup(self.netdev, 0xFFFF).ops.id.string_(), b"ingress")

    def _add_u32_filter(self, chain: int):
        flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL

        msg = _tcmsg()
        msg["index"] = self.index
        msg["parent"] = 0x10000

        u32 = plugins["u32"]
        kwarg = dict(
            protocol=protocols.ETH_P_ALL,
            target=0x10020,
            keys=["0x0/0x0+0"],
            action="ok",
        )
        u32.fix_msg(msg, kwarg)
        options = u32.get_parameters(kwarg)

        msg["attrs"].append(["TCA_KIND", "u32"])
        msg["attrs"].append(["TCA_OPTIONS", options])
        if chain > 0:
            msg["attrs"].append(["TCA_CHAIN", chain])

        return tuple(self.ns.nlm_request(msg, msg_type=RTM_NEWTFILTER, msg_flags=flags))

    def test_for_each_tcf_chain(self):
        # tc qdisc add dev dummy0 root handle 1: htb
        try:
            self.ns.tc("add", kind="htb", index=self.index, handle="1:")
        except NetlinkError:
            self.skipTest(
                "kernel does not support Hierarchical Token Bucket (CONFIG_NET_SCH_HTB)"
            )
        # Before Linux kernel commit 6529eaba33f0 ("net: sched: introduce tcf
        # block infractructure") (in v4.13), struct tcf_block didn"t exist.
        qdisc = qdisc_lookup(self.netdev, 0x1)
        try:
            block = Object(
                self.prog, "struct htb_sched *", qdisc.privdata.address_
            ).block
        except AttributeError:
            self.skipTest("struct tcf_block does not exist")
        # add chain 0
        try:
            self._add_u32_filter(0)
        except NetlinkError:
            self.skipTest("kernel does not support u32 filter (CONFIG_NET_CLS_U32)")
        # check if kernel supports multichain
        if not block.prog_.type("struct tcf_block").has_member("chain_list"):
            try:
                chains = list(for_each_tcf_chain(block))
            except AttributeError:
                self.skipTest("struct tcf_chain does not exist")

            self.assertEqual(len(chains), 1)

            chain = chains[0]
            self.assertEqual(chain.filter_chain.ops.kind.string_(), b"u32")
            self.assertEqual(chain.index, 0)
            return
        # add chain 1 and 2
        self._add_u32_filter(1)
        self._add_u32_filter(2)

        indices = [0, 1, 2]
        chains = list(for_each_tcf_chain(block))
        self.assertEqual(len(chains), len(indices))

        for index, chain in zip(indices, chains):
            self.assertEqual(chain.filter_chain.ops.kind.string_(), b"u32")
            self.assertEqual(chain.index, index)


class _tcmsg(nlmsg):
    prefix = "TCA_"

    fields = (
        ("family", "B"),
        ("pad1", "B"),
        ("pad2", "H"),
        ("index", "i"),
        ("handle", "I"),
        ("parent", "I"),
        ("info", "I"),
    )

    # Currently pyroute2 doesn't support TCA_CHAIN.  Use this tailored version
    # of class tcmsg for now.
    nla_map = (
        ("TCA_UNSPEC", "none"),
        ("TCA_KIND", "asciiz"),
        ("TCA_OPTIONS", "get_options"),
        ("TCA_STATS", "none"),
        ("TCA_XSTATS", "none"),
        ("TCA_RATE", "none"),
        ("TCA_FCNT", "none"),
        ("TCA_STATS2", "none"),
        ("TCA_STAB", "none"),
        ("TCA_PAD", "none"),
        ("TCA_DUMP_INVISIBLE", "none"),
        ("TCA_CHAIN", "uint32"),
    )

    @staticmethod
    def get_options(self, *argv, **kwarg):
        del self, argv, kwarg
        return cls_u32.options
