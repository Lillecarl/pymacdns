"""Addresses of the interfaces named by [server] listen_interfaces.

The VM bridges macOS creates (bridge100 for Virtualization.framework's NAT)
hand out their own address as the guests' DNS server. mDNSResponder serves
it through a proxy bound to the wildcard address on port 53, without
SO_REUSEADDR, so that bind fails while we hold any address on port 53 and
the guests get no DNS. Serving the bridge addresses ourselves replaces it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from fnmatch import fnmatchcase
from typing import Final

INTERFACE_ADDRESS_PATTERN: Final = r"State:/Network/Interface/[^/]+/IPv[46]"


def select_addresses(
    entries: Mapping[str, Iterable[str]], patterns: Iterable[str]
) -> set[str]:
    """Bindable hosts of the interfaces any pattern matches.

    A link-local IPv6 address binds only with its scope, so it carries
    %ifname.
    """
    patterns = list(patterns)
    hosts: set[str] = set()
    for ifname, addresses in entries.items():
        if not any(fnmatchcase(ifname, pattern) for pattern in patterns):
            continue
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip.version == 6 and ip.is_link_local:
                hosts.add(f"{address}%{ifname}")
            else:
                hosts.add(address)
    return hosts


def read_interface_addresses() -> dict[str, list[str]]:
    """Interface name to addresses, from State:/Network/Interface/*/IPv[46]."""
    from SystemConfiguration import (
        SCDynamicStoreCopyKeyList,
        SCDynamicStoreCopyValue,
        SCDynamicStoreCreate,
    )

    store = SCDynamicStoreCreate(None, "pymacdns-interfaces", None, None)
    if store is None:
        raise OSError("configd is unreachable")
    entries: dict[str, list[str]] = {}
    for key in SCDynamicStoreCopyKeyList(store, INTERFACE_ADDRESS_PATTERN) or []:
        ifname = str(key).split("/")[3]
        info = dict(SCDynamicStoreCopyValue(store, str(key)) or {})
        entries.setdefault(ifname, []).extend(
            str(address) for address in info.get("Addresses") or []
        )
    return entries
