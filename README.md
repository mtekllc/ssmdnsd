# ssmdnsd (Super Simple mDNS daemon)

A Super Simple Multicast DNS server for Linux. A Much smaller and lighter weight than Avahi.

`ssmdnsd` is a remake is inspired by `minimdnsd` (MDNS server) https://github.com/cnlohr/minimdnsd

`ssmdnsd` serves as an mDNS hostname responder. When running, it allows any computer on your network
 to resolve `your_hostname.local` to the IP address of the interface that received the request.
 By default, `ssmdnsd` responds using the hostname specified in the system path `/etc/hostname`.

 - Uses no CPU unless event requested.
 - Only needs around 32kB RAM.
 - Compiles to between 15-45kB
 - Can run as a user or root.
 - Default zero config e.g. watches for `/etc/hostname` changes.  (Optionally: Can use -h to also watch for a additional host aliases)
 - Performs `UNICAST-RESPONSE` if requested, otherwise a `MULTICAST-RESPONSE` is generated

Relevant RFCs:
- Multicast DNS https://datatracker.ietf.org/doc/html/rfc6762
- Domain Name System (DNS) IANA Considerations https://datatracker.ietf.org/doc/html/rfc5395
- Domain Names, Implementation and Specification https://datatracker.ietf.org/doc/html/rfc1035
- Dynamic Updates in DNS https://datatracker.ietf.org/doc/html/rfc2136

## General Motivation

1. To obviate need for avahi-daemon
2. To provide an mDNS hostname responder for embedded systems

## Building

### Prerequisites

 * build-essential (make + GCC + system headers)

### Build process

```
./bootstrap.sh && ./configure && make
```

Optionally execute `make install` to install `ssmdnsd` to your local system including systemd service file

