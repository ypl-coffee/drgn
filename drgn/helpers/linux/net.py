# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Networking
----------

The ``drgn.helpers.linux.net`` module provides helpers for working with the
Linux kernel networking subsystem.
"""

import operator
from typing import Iterator, Union

from drgn import NULL, IntegerLike, Object, Program
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list_nulls import hlist_nulls_for_each_entry

__all__ = (
    "netdev_get_by_index",
    "netdev_get_by_name",
    "sk_fullsock",
    "sk_nulls_for_each",
)


_NETDEV_HASHBITS = 8
_NETDEV_HASHENTRIES = 1 << _NETDEV_HASHBITS


def netdev_get_by_index(
    prog_or_net: Union[Program, Object], ifindex: IntegerLike
) -> Object:
    """
    Get the network device with the given interface index number.

    :param prog_or_net: ``struct net *`` containing the device, or
        :class:`Program` to use the initial network namespace.
    :param ifindex: Network interface index number.
    :return: ``struct net_device *`` (``NULL`` if not found)
    """
    if isinstance(prog_or_net, Program):
        prog_or_net = prog_or_net["init_net"]
    if isinstance(ifindex, Object):
        ifindex = ifindex.read_()

    head = prog_or_net.dev_index_head[
        operator.index(ifindex) & (_NETDEV_HASHENTRIES - 1)
    ]
    for netdev in hlist_for_each_entry("struct net_device", head, "index_hlist"):
        if netdev.ifindex == ifindex:
            return netdev

    return NULL(prog_or_net.prog_, "struct net_device *")


def netdev_get_by_name(prog_or_net: Union[Program, Object], name: str) -> Object:
    """
    Get the network device with the given interface name.

    :param prog_or_net: ``struct net *`` containing the device, or
        :class:`Program` to use the initial network namespace.
    :param name: Network interface name.
    :return: ``struct net_device *`` (``NULL`` if not found)
    """
    if isinstance(prog_or_net, Program):
        prog_or_net = prog_or_net["init_net"]

    for i in range(_NETDEV_HASHENTRIES):
        head = prog_or_net.dev_name_head[i]
        for name_node in hlist_for_each_entry("struct netdev_name_node", head, "hlist"):
            if name_node.name.string_().decode() == name:
                return name_node.dev

    return NULL(prog_or_net.prog_, "struct net_device *")


def sk_fullsock(sk: Object) -> bool:
    """
    Check whether a socket is a full socket, i.e., not a time-wait or request
    socket.

    :param sk: ``struct sock *``
    """
    prog = sk.prog_
    state = sk.__sk_common.skc_state.value_()
    return state != prog["TCP_SYN_RECV"] and state != prog["TCP_TIME_WAIT"]


def sk_nulls_for_each(head: Object) -> Iterator[Object]:
    """
    Iterate over all the entries in a nulls hash list of sockets specified by
    ``struct hlist_nulls_head`` head.

    :param head: ``struct hlist_nulls_head *``
    :return: Iterator of ``struct sock *`` objects.
    """
    for sk in hlist_nulls_for_each_entry(
        "struct sock", head, "__sk_common.skc_nulls_node"
    ):
        yield sk
