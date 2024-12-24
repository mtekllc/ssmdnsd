# ssmdnsd (Super Simple mDNS daemon)

Super Simple Multicast DNS server for Linux. A Much smaller and lighter weight than Avahi.

ssmdnsd is a remake is inspired by minimdnsd (MDNS server) https://github.com/cnlohr/minimdnsd

ssmdnsd is primarily a mDNS hostname responder - e.g. run this, and any computer on your network can say `ping your_hostname.local`  and it will resolve to your request with the IP address for the interface which the request was received on. By default, the name for which the ssmdnsd responds to is whatever name is found in the system path `/etc/hostname`.

 * Uses no CPU unless event requested.
 * Only needs around 32kB RAM.
 * Compiles to between 15-45kB
 * Can run as a user or root.
 * Default zero config e.g. watches for `/etc/hostname` changes.  (Optionally: Can use -h to also watch for a additional host aliases)
 * Performs `UNICAST-RESPONSE` if requested, otherwise a `MULTICAST-RESPONSE` is generated
 * Works on IPv6

<sup>Note 1: ssmdnsd facilitates resolving host names e.g. `hostname.local` to IP address.</sup>

<sup>Note 2: ssmdnsd does not support service discovery at this time.</sup>

## General Motivation

1. To obviate need for avahi-daemon
2. To provide an mDNS server on very simple embedded systems

## Building

### Prerequisites

 * build-essential (make + GCC + system headers)

### Build process

```
./bootstrap.sh && ./configure && make
```

Optionally disable IPv6 support with `./configure --enable-ipv4-only`

Optionally execute `make install` to install `ssmdnsd` to your local system including systemd service file

