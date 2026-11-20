# Embedded gVisor netstack

This directory contains the gVisor netstack dependency closure used by IMS.
It is derived from [gVisor commit `e0cb0095337340f333b83fb2d81880456d4f65dc`](https://github.com/gvisor/gvisor/commit/e0cb0095337340f333b83fb2d81880456d4f65dc).

Only the userspace IPv4/IPv6, TCP, UDP, channel link endpoint, static address
and route handling, fragmentation, ICMP echo, inbound ICMP error/PMTU handling,
and their supporting packages are retained.
IMS keeps IKE, ESP policy, replay protection, and the outer data planes outside
this directory.

This is intentionally not a general-purpose netstack. It does not include
iptables/nftables, NAT, conntrack, ICMP sockets, raw sockets, packet sockets,
ARP, NDP, IGMP/MLD, multicast membership, bridge support, dynamic address
discovery, or checkpoint/restore. The IMS integration supplies negotiated
inner addresses and direct routes.

The source keeps the upstream copyright headers and complete gVisor license
text, including the Apache 2.0, MIT-style, and BSD notices used by copied files.
Generated Go and assembly files required by the standard Go toolchain are
checked in so application builds do not require Bazel.

The embedded subset is compiled in CI-compatible mode for Linux, macOS, and
Windows on both amd64 and arm64. Updating the upstream commit requires copying
the same dependency closure again and rerunning that six-target build matrix.
