# tcpip-stack — notes

## overview
TCP/IP stack from scratch to understand low-level networking and investigate where latency and jitter live in the stack
runs in a Docker container (ubuntu) because macOS doesn't have `/dev/net/tun` - ARM64 container

## progress

**1 — TAP device**
open `/dev/net/tun`, `ioctl` it into a TAP interface, `read()` raw Ethernet frames in a loop. just hex-dumped them at first.

**2 — Ethernet + ARP**
parse Ethernet frames, reply to ARP requests so my fake device (`10.0.0.5`, MAC `aa:bb:cc:dd:ee:ff`) shows up on the network. keep an ARP cache (IP → MAC)

**3 — IPv4**
parse the IPv4 header, verify the Internet checksum

**4 — UDP**
parse the UDP header, slice the payload with `std::span` (no copy). built a lock-free single-producer/single-consumer ring buffer with atomics
added a latency benchmark — wanted `rdtsc` but that's x86-only and my container is ARM, so `std::chrono` instead

**TCP (in progress)**
parse the TCP header, track connections in a hash map keyed by the (src ip, src port, dst ip, dst port) 4-tuple — needed a custom `std::hash` for that 
each connection has a control block: state + sequence numbers - wrote the state machine for the 3-way handshake
**the handshake now completes against a `nc` client**, verified with `tcpdump`
currently working on data transfer

## still to do
- finish TCP data transfer + teardown (FIN)
- retransmission timers (— the main loop blocks on `read()`)
- kernel bypass (AF_XDP), cache-line alignment, no allocations on the hot path
