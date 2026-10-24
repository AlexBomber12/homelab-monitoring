#!/usr/bin/env python3
"""Verify explicit RFC1918 IPv4 peer address; never resolve untrusted names."""
from __future__ import annotations
import ipaddress
import sys

def validate_peer_ip(s: str) -> str:
    try:
        addr = ipaddress.IPv4Address(s)
    except ipaddress.AddressValueError as e:
        raise ValueError("peer address must be a literal IPv4 address") from e
    if not any(addr in subnet for subnet in (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )):
        raise ValueError("peer address must be RFC1918")
    return str(addr)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("pass exactly one IPv4 address")
        validate_peer_ip(sys.argv[1])
    except ValueError:
        print("PEER IPV4: INVALID", file=sys.stderr)
        raise SystemExit(2)
    print("PEER IPV4: VERIFIED")
