# SSMDNSD (Super Simple mDNS Daemon)

A super simple multicast DNS server for Linux that is smaller and lighter weight than Avahi, designed to provide an mDNS hostname responder mechanism for embedded systems with limited resources.

`ssmdnsd` is a remake inspired by [`minimdnsd`](https://github.com/cnlohr/minimdnsd) (MDNS server).

`ssmdnsd` serves as an mDNS hostname responder. When running, it allows any computer on your network to resolve `your_hostname.local` to the IP address of the interface that received the request. By default, `ssmdnsd` responds using the hostname specified in the system path `/etc/hostname`.

- Uses no CPU unless an event is requested.
- Only needs around 32kB RAM.
- Compiles to between 15-45kB.
- Can run as a user or root.
- Default zero config (e.g., watches for `/etc/hostname` changes). Optionally, it can use `-n` to watch for additional host aliases.
- Performs `UNICAST-RESPONSE` if requested; otherwise, a `MULTICAST-RESPONSE` is generated.

## Program Options
- `-n`: Specify a hostname override instead of using `/etc/hostname`. You can launch multiple instances to get multiple overrides.
- `-i`: Specify an interface name to listen on rather than all interfaces (default).
- `-f`: Run the program in the foreground.
- `-p`: Specify a file system path to store the program's PID. If set, subsequent executions using the same path will verify that an instance of the program is not already running.
- `-4`: Disable IPv6 operation.
- `-v`: Increase program verbosity.

## Relevant RFCs
- [Multicast DNS (RFC 6762)](https://datatracker.ietf.org/doc/html/rfc6762)
- [Domain Name System (DNS) IANA Considerations (RFC 5395)](https://datatracker.ietf.org/doc/html/rfc5395)
- [Domain Names, Implementation and Specification (RFC 1035)](https://datatracker.ietf.org/doc/html/rfc1035)
- [Dynamic Updates in DNS (RFC 2136)](https://datatracker.ietf.org/doc/html/rfc2136)

## Building

### Prerequisites

- `build-essential` (make + GCC + system headers)

### Build Process

```bash
./bootstrap.sh && ./configure && make
