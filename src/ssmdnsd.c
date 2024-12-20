//
// MIT License
//
// Copyright 2024 <>< Charles Lohr
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the “Software”), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
// The following is mostly a demo of:
//  * Use of inotify to detect changes of /etc/hostname
//  * Use of `getifaddrs` to iterate through all available interfaces
//  * Use of `NETLINK_ROUTE` and `RTMGRP_IPV4_IFADDR` and `RTMGRP_IPV6_IFADDR`
//    to monitor for any new network interfaces or addresse.
//  * Use of multicast in IPv4 and IPv6 to join a multicast group
//  * Leveraging `poll` to have programs that are completely asleep when not
//    actively needed.
//  * Use of `recvmsg` to get the interface and address that a UDP packet is
//    received on
//  * Use optarg to parse command-line arguments.
//  * But it does implement a fully function mnds server that advertises your
//    host to other peers on your LAN!
//  * Also, it's shim "dns server" that bridges DNS to MDNS.
//

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/in6.h>
#include <limits.h>
#include <fcntl.h>

// for detecting interfaces going away or coming back.
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

// for detecting "hostname" change.
#include <sys/inotify.h>

// for DNS -> MDNS forwarding we use fork/wait
#include <sys/wait.h>

#include "config.h"

#define MAX_MDNS_PATH           (HOST_NAME_MAX+1)
#define MDNS_PORT               5353
#define RESOLVER_PORT           53
#define RESOLVER_IP             "127.0.0.67"

#if __BYTE_ORDER == __BIG_ENDIAN
#define MDNS_BRD_ADDR ((in_addr_t) 0xe00000fb)  // 224.0.0.251
#else
#define MDNS_BRD_ADDR ((in_addr_t) 0xfb0000e0)  // 224.0.0.251
#endif

static const char * hostname_override;
static char hostname[HOST_NAME_MAX + 1] = {0};
static int hostnamelen = 0;
static int hostname_watch = 0;
static int sdsock = 0;
static int is_ipv4_only = 0;
static int is_bound_6 = 0;
static int sdifaceupdown = 0;
static int resolver = 0;

// for multicast queries, and multicast replies.
struct sockaddr_in sin_multicast = {
        .sin_family = AF_INET,
        .sin_addr =
        {MDNS_BRD_ADDR},
        .sin_port = 0
};

/**
 * @brief it reads default system path /etc/hostname and attempts to use name
 *        provided as the name we listen listen and match with
 *
 *        note the name/match can be over-ridden by command line option
 */
static void initialize_hostname(void)
{
        int j = 0;
        int rd = 0;
        int fh = 0;

        if (hostname_override) {
                hostnamelen = strlen(hostname_override);
                if (hostnamelen >= HOST_NAME_MAX) {
                        hostnamelen = HOST_NAME_MAX - 1;
                }
                memcpy(hostname, hostname_override, hostnamelen);
                printf("using hostname from command line argument: \"%s.local\"\n", hostname);
                return;
        }

        if ((fh = open("/etc/hostname", O_RDONLY)) < 1) {
                goto hostnamefault;
        }

        rd = read(fh, hostname, HOST_NAME_MAX);

        close(fh);

        if (rd <= 0) {
                goto hostnamefault;
        }

        hostnamelen = rd;

        for (j = 0; j < rd; j++) {
                char c = hostname[j];
                if (c == '\n') // truncate at newline
                {
                        hostnamelen = j;
                } else if (c >= 'A' && c <= 'Z') { // convert to lowercase
                        hostname[j] = c + 'z' - 'Z';
                }
        }

        hostname[hostnamelen] = 0;

        printf("responding to hostname: \"%s.local\"\n", hostname);

        return;

hostnamefault:

        fprintf(stderr, "error: can't stat /etc/hostname\n");
        return;
}

#if (DISABLE_IPV6 == 0)
/**
 * @brief
 *
 * @param interface
 */
static void multicast_addr_add6(int interface)
{
        // multicast ipv6 addr = ff01:0:0:0:0:0:0:fb

        struct ipv6_mreq mreq6 = {
                .ipv6mr_multiaddr =
                {
                        {
                                { 0xff, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}
                        }
                },
                .ipv6mr_interface = interface,
        };

        if (setsockopt(sdsock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *) &mreq6,
                        sizeof(mreq6)) == -1) {
                fprintf(stderr, "warning: could not join ipv6 membership on "
                        "interface %d (%d %s)\n", interface, errno, strerror(errno));
        }
}
#endif

/**
 * @brief
 *
 * @param saddr
 */
static void multicast_addr_add(struct in_addr * saddr)
{
        struct ip_mreq mreq = {
                .imr_multiaddr.s_addr = MDNS_BRD_ADDR,
                .imr_interface = *saddr
        };

        if (setsockopt(sdsock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &mreq,
                        sizeof(mreq)) == -1) {
                char * addr = inet_ntoa(*saddr);
                fprintf(stderr, "warning: could not join membership to %s / code %d (%s)\n",
                        addr, errno, strerror(errno));
        }
}

/**
 * @brief
 *
 * @param testaddr
 *
 * @return
 */
static int is_ipv4_local(struct in_addr * testaddr)
{
        uint32_t check = ntohl(testaddr->s_addr);
        if ((check & 0xff000000) == 0x7f000000) return 1; // 127.x.x.x (Link Local, but still want to join)
        if ((check & 0xff000000) == 0x0a000000) return 1; // 10.x.x.x
        if ((check & 0xfff00000) == 0xac100000) return 1; // 172.[16-31].x.x
        if ((check & 0xffff0000) == 0xc0a80000) return 1; // 192.168.x.x
        if ((check & 0xffff0000) == 0xa9fe0000) return 1; // 169.254.x.x (RFC5735)
        return 0;
}

#if (DISABLE_IPV6 == 0)
/**
 * @brief
 *
 * @param addr
 *
 * @return
 */
static int is_ipv6_local(struct in6_addr * addr)
{
        return IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_SITELOCAL(addr);
}
#endif

/**
 * @brief
 *
 * @param addr
 *
 * @return
 */
static void multicast_addr_check(struct sockaddr * addr)
{
        if (!addr) {
                return;
        }

        int family = addr->sa_family;

        if (family == AF_INET) {
                char addrbuff[INET_ADDRSTRLEN + 1] = {0};
                struct sockaddr_in * sa4 = (struct sockaddr_in*) addr;
                const char * addrout = inet_ntop(family, &sa4->sin_addr, addrbuff, sizeof( addrbuff) - 1);
                if (!(is_ipv4_local(&sa4->sin_addr))) {
                        return;
                }
                printf("multicast adding address: (%s)\n", addrout);
                multicast_addr_add(&sa4->sin_addr);
        }
#if (DISABLE_IPV6 == 0)
        else if (family == AF_INET6 && !is_ipv4_only) {
                char addrbuff[INET6_ADDRSTRLEN + 1] = {0};
                struct sockaddr_in6 * sa6 = (struct sockaddr_in6 *) addr;
                const char * addrout = inet_ntop(family, &sa6->sin6_addr, addrbuff, sizeof( addrbuff) - 1);
                if (!(is_ipv6_local(&sa6->sin6_addr))){
                        return;
                }
                printf("multicast adding interface: %u (%s)\n", sa6->sin6_scope_id, addrout);
                multicast_addr_add6(sa6->sin6_scope_id);
        }
#endif
        return;
}

/**
 * @brief it loops through our interface list and passess to the multicast add
 *        method for inclusion
 */
static int request_interfaces()
{
        struct ifaddrs * ifaddr = 0;

        if (getifaddrs(&ifaddr) < 0) {
                fprintf(stderr, "error: could not query devices\n");
                return -1;
        }

        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                struct sockaddr * addr = ifa->ifa_addr;
                multicast_addr_check(addr);
        }

        freeifaddrs(ifaddr);

        return 0;
}

/**
 * @brief process kernel netlink messages
 */
static void handle_netlink_recv()
{
        int len = 0;
        struct nlmsghdr *nlh = NULL;
        char buffer[4096] = {0};

        nlh = (struct nlmsghdr *)buffer;

        while ((len = recv(sdifaceupdown, nlh, sizeof(buffer), MSG_DONTWAIT)) > 0) {
                // technique is based around https://stackoverflow.com/a/2353441/2926815
                while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
                        if (nlh->nlmsg_type == RTM_NEWADDR) {
                                struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
                                struct rtattr *rth = IFA_RTA(ifa);

                                int rtl = IFA_PAYLOAD(nlh);

                                while (rtl && RTA_OK(rth, rtl)) {
                                        if (/*rth->rta_type == IFA_LOCAL || */ rth->rta_type == IFA_ADDRESS) {
                                                char name[IFNAMSIZ] = {0};
                                                if_indextoname(ifa->ifa_index, name);
                                                int pld = RTA_PAYLOAD(rth);
                                                // record the index.
                                                if (ifa->ifa_family == AF_INET) {
                                                        struct sockaddr_in sai = {0};
                                                        sai.sin_family = AF_INET;
                                                        memcpy(&sai.sin_addr, RTA_DATA(rth), pld);
                                                        multicast_addr_check((struct sockaddr*) &sai);
                                                }
#if (DISABLE_IPV6 == 0)
                                                else if (ifa->ifa_family == AF_INET6) {
                                                        int ifindex = ifa->ifa_index;
                                                        struct sockaddr_in6 sai = {0};
                                                        sai.sin6_family = AF_INET6;
                                                        sai.sin6_scope_id = ifindex;
                                                        memcpy(&sai.sin6_addr, RTA_DATA(rth), pld);
                                                        multicast_addr_check((struct sockaddr*) &sai);
                                                }
#endif
                                        }
                                        rth = RTA_NEXT(rth, rtl);
                                }
                        }
                        nlh = NLMSG_NEXT(nlh, len);
                }
                nlh = (struct nlmsghdr *)buffer; // re-align with buffer
        }
}

/**
 * @brief MDNS functions from esp32xx
 *
 * @param baseptr
 * @param eptr
 * @param topop
 * @param len
 * @return
 */
uint8_t * mdns_path_parse(uint8_t *baseptr, uint8_t *eptr, char *topop, int *len)
{
        int l = 0;
        int j = 0;

        *len = 0;

        while (baseptr != eptr) {
                // see how long the string we should read is.
                l = *(baseptr++);

                // zero-length strings indicate end-of-string.
                if (l == 0) {
                        break;
                }

                if (*len + l >= MAX_MDNS_PATH) {
                        return 0;
                }

                // if not our first time through, add a '.'
                if (*len != 0) {
                        *(topop++) = '.';
                        (*len)++;
                }

                for (j = 0; j < l; j++) {
                        if (baseptr[j] >= 'A' && baseptr[j] <= 'Z') {
                                topop[j] = baseptr[j] - 'A' + 'a';
                        } else {
                                topop[j] = baseptr[j];
                        }
                }

                // move along in the string to check if there are more strings to concatenate
                topop += l;
                baseptr += l;
                *len += l;
        }

        *topop = 0;

        return baseptr;
}

/**
 * @brief fabricate a response to request that matched our name
 *
 * @param sock
 * @param sender
 * @param sl
 * @param record_type
 * @param addr_type
 * @param xactionid
 * @param namestartptr
 * @param stlen
 * @param in_any
 */
static void respond(int sock, struct sockaddr_in6 *sender, int sl, int record_type,
        int addr_type, uint16_t xactionid, uint8_t *str_name, int str_name_len, void *in_any)
{
        uint8_t outbuff[MAX_MDNS_PATH * 2 + 128];
        uint8_t *obptr = outbuff;
        uint16_t *obb = (uint16_t*)outbuff;
        struct in_addr *local_addr_4 = in_any;
        struct in6_addr *local_addr_6 = in_any;

        int sendA = (record_type == 1 /*A*/ && addr_type == IPPROTO_IP);
#if (DISABLE_IPV6 == 0)
        int sendAAAA = (record_type == 28 /*AAAA*/ && addr_type == IPPROTO_IPV6);
#else
        int sendAAAA = 0;
#endif

        if (!sendA && !sendAAAA) {
                return;
        }

        // for ipv4 or 6 responses we always have this in common
        if (sendA || sendAAAA) {
                *(obb++) = xactionid;
                *(obb++) = htons(0x8400); // authortative response.
                *(obb++) = 0;
                *(obb++) = htons(1); // 1 answer.
                *(obb++) = 0;
                *(obb++) = 0;

                obptr = (uint8_t*) obb;

                // Answer
                memcpy(obptr, str_name, str_name_len + 1);
                obptr += str_name_len + 1;
                *(obptr++) = 0;
                *(obptr++) = 0x00;
                *(obptr++) = (sendA ? 0x01 : 0x1c); // A record
                *(obptr++) = 0x80;
                *(obptr++) = 0x01; // flush cache + in ptr.
                *(obptr++) = 0x00;
                *(obptr++) = 0x00; // TTL
                *(obptr++) = 0x00;
                *(obptr++) = 240; // 240 seconds (4 minutes)
        }

        // but if 4
        if (sendA) {
                *(obptr++) = 0x00;
                *(obptr++) = 0x04; // Size 4 (IP)
                memcpy(obptr, &local_addr_4->s_addr, 4);
                obptr += 4;
        }
#if (DISABLE_IPV6 == 0)
        else if (sendAAAA) {
                *(obptr++) = 0x00;
                *(obptr++) = 0x10; // Size 16 (IPv6)
                memcpy(obptr, &local_addr_6->s6_addr, 16);
                obptr += 16;
        }
#endif

        sendto(sock, outbuff, obptr - outbuff, MSG_NOSIGNAL, (struct sockaddr*)sender, sl);

        // use another socket to send the response
        int socks_to_send = socket(AF_INET, SOCK_DGRAM, 0);
        //struct ip_mreqn txif = { 0 };
        //txif.imr_multiaddr.s_addr = MDNS_BRD_ADDR;
        //txif.imr_address.s_addr = local_addr_4.s_addr;
        //txif.imr_ifindex = rxinterface;
        //rxinterface = rxinterface; // we aren't using this now, see note below
        // With IP_MULTICAST_IF you can either pass in an ip_mreqn, or just the local_addr4

        // we tried to do the full txif for clarity / example but, it seems to cause issues?
        if (setsockopt(socks_to_send, IPPROTO_IP, IP_MULTICAST_IF, local_addr_4, sizeof(struct in_addr)) != 0) {
                fprintf(stderr, "warning: could not set IP_MULTICAST_IF for reply\n");
        }

        int optval = 1;
        if (setsockopt(socks_to_send, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof( optval)) != 0) {
                fprintf(stderr, "warning: could not set SO_REUSEPORT for reply\n");
        }

        struct sockaddr_in sin = {
                .sin_family = AF_INET,
                .sin_addr =
                { INADDR_ANY},
                .sin_port = htons(MDNS_PORT)
        };

        if (bind(socks_to_send, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
                fprintf(stderr, "warning: when sending reply, "
                        "could not bind to IPv4 MDNS port (%d %s)\n", errno, strerror(errno));
        }

        if (sendto(socks_to_send, outbuff, obptr - outbuff, MSG_NOSIGNAL,
                (struct sockaddr*) &sin_multicast, sizeof(sin_multicast)) != obptr - outbuff) {
                fprintf(stderr, "warning: could not send multicast reply for MDNS query\n");
        }

        close(socks_to_send);

}

static void handle_message_recv(int sock, int is_resolver)
{
        uint8_t buffer[9036] = {0}; // per RFC-6762 Section 6.1
        char path[MAX_MDNS_PATH+1] = {0};
        int i = 0;
        int stlen = 0;
        uint8_t cmbuf[1024] = {0};
        struct sockaddr_in6 sender = {0};
        struct in_addr local_addr_4 = {0};
        int addr_type = 0; // none
        void *in_any = NULL;
        struct cmsghdr *cmsg = NULL;
#if (DISABLE_IPV6 == 0)
        struct in6_addr local_addr_6 = {0};
#endif
        socklen_t sl = sizeof(sender);

        /* using recvmsg, this is a little tricky, to avoid having a separate
         * socket for every single interface, we can instead, just recvmsg and
         * discern which interface the message originated */

        // if you want access to the data you need to init the msg_iovec fields
        struct iovec iov = {
                .iov_base = buffer,
                .iov_len = sizeof(buffer),
        };

        struct msghdr msghdr = {
                .msg_name = &sender,
                .msg_namelen = sizeof(sender),
                .msg_control = cmbuf,
                .msg_controllen = sizeof( cmbuf),
                .msg_flags = 0,
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        int r = recvmsg(sock, &msghdr, 0);

        if (r < 0 || msghdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
                return; // this should never happen
        }

        if (r < 12) {
                return; // runt packet
        }

        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
                // ignore the control headers that don't match what we want
                // see https://stackoverflow.com/a/5309155/2926815
                if (cmsg->cmsg_type != IP_PKTINFO &&
                        (cmsg->cmsg_type != IPV6_PKTINFO || cmsg->cmsg_type != IPV6_RECVPKTINFO)) {
                        continue;
                }
                if (cmsg->cmsg_level == IPPROTO_IP) {
                        struct in_pktinfo * pi = (struct in_pktinfo *) CMSG_DATA(cmsg);
                        // at this point, peeraddr is the source sockaddr
                        // pi->ipi_spec_dst is the destination in_addr
                        // pi->ipi_addr is the destination address, in_addr
                        local_addr_4 = pi->ipi_spec_dst;
                        in_any = &pi->ipi_spec_dst;
                        // pi->ipi_addr is actually the multicast address
                        addr_type = IPPROTO_IP;
                }
#if (DISABLE_IPV6 == 0)
                else if (cmsg->cmsg_level == IPPROTO_IPV6) {
                        // note: some build platforms do not include this.
                        struct in6_pktinfo_shadow {
                                struct in6_addr ipi6_addr; /* src/dst IPv6 address */
                                unsigned int ipi6_ifindex; /* send/recv interface index */
                        };
                        struct in6_pktinfo_shadow * pi = (struct in6_pktinfo_shadow *) CMSG_DATA(cmsg);
                        local_addr_6 = pi->ipi6_addr;
                        in_any = &pi->ipi6_addr;
                        addr_type = IPPROTO_IPV6;
                }
#endif
        }

        if (!in_any) {
                fprintf(stderr, "error: no ipv4/6 address set\n");
                return; // insufficient source address info
        }

        uint16_t * psr = (uint16_t*) buffer;
        uint16_t xactionid = ntohs(psr[0]);
        uint16_t flags = ntohs(psr[1]);
        uint16_t questions = ntohs(psr[2]);

        // we discard answers
        //uint16_t answers = ntohs( psr[3] );
        // note: index 12 bytes in, we can do a direct reply
        uint8_t * dataptr = (uint8_t*) buffer + 12;
        uint8_t * dataend = dataptr + r - 12;

        // MDNS reply (we are a server, not a client, so discard)
        if (flags & 0x8000) {
                return;
        }

        int is_a_suitable_mdns_record_query = 0;
        int found = 0;

        // the Query
        for (i = 0; i < questions; i++) {
                uint8_t * namestartptr = dataptr;
                // work our way through
                dataptr = mdns_path_parse(dataptr, dataend, path, &stlen);

                // make sure there is still room left for the rest of the record
                if (!dataptr || dataend - dataptr < 4) {
                        break;
                }

                int pathlen = strlen(path);

                if (pathlen < 6 || strcmp(path + pathlen - 6, ".local") != 0) {
                        continue;
                }

                uint16_t record_type = (dataptr[0] << 8) | dataptr[1];

                // record class is not used
                //uint16_t record_class = ( dataptr[2] << 8 ) | dataptr[3];

                if ((record_type == 1) || (!is_ipv4_only && (record_type == 28))) {
                        is_a_suitable_mdns_record_query = 1;
                }

                const char * path_first_dot = path;
                const char * cpp = path;

                while (*cpp && *cpp != '.') {
                        cpp++;
                }

                int dotlen = 0;

                if (*cpp == '.') {
                        path_first_dot = cpp + 1;
                        dotlen = path_first_dot - path - 1;
                } else {
                        path_first_dot = 0;
                }

                if (hostname[0]
                        && dotlen
                        && (dotlen == hostnamelen)
                        && (memcmp(hostname, path, dotlen) == 0)) {
                        respond(sock, &sender, sl, record_type, addr_type, xactionid, namestartptr, stlen, in_any);
                        found = 1;
                }
        }

        // note: we could also reply with services here

        // but, if we aren't sending a response, and we're a resolver, we have to do more work.
        //	printf( "CHECK: %d %d %d %d\n", found, is_resolver, resolver, is_an_a_mdns_record_query );
        if (!found && is_resolver && resolver) {
                // note: if we are resolving, broadcast to the rest of the network
                // note: only IPv4 records are supported as AAAA records seem to jank things up
                if (is_a_suitable_mdns_record_query) {
                        int pid_of_resolver = fork();

                        if (pid_of_resolver == 0) {
                                /* this is a fork()'d pid - from here on out we have
                                 * to make sure to exit */
                                int socks_to_send = socket(AF_INET, SOCK_DGRAM, 0);
                                if (!socks_to_send) {
                                        fprintf(stderr, "warning: could not create multicast message\n");
                                        exit(1);
                                }

                                int loopbackEnable = 0;
                                if (setsockopt(socks_to_send, IPPROTO_IP, IP_MULTICAST_LOOP, &loopbackEnable, sizeof( loopbackEnable)) < 0) {
                                        fprintf(stderr, "warning: cannot prevent self-looping of mdns packets\n");
                                        exit(1);
                                }

                                struct timeval tv = {.tv_sec = 3};
                                if (setsockopt(socks_to_send, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof( tv)) < 0) {
                                        fprintf(stderr, "warning: could not set sock option on repeated socket\n");
                                        close(socks_to_send);
                                        exit(1);
                                }

                                if (sendto(socks_to_send, buffer, r, MSG_NOSIGNAL, (struct sockaddr*) &sin_multicast, sizeof( sin_multicast)) < 0) {
                                        fprintf(stderr, "warning: could not repeat as MDNS request\n");
                                        close(socks_to_send);
                                        exit(1);
                                }

                                for (;;) {
                                        r = recv(socks_to_send, buffer, sizeof(buffer), 0);
                                        if (r <= 0) {
                                                break;
                                        }

                                        // If the packet is a reply, not a question, we can forward it back to the asker.
                                        uint16_t flags = ntohs(((uint16_t*) buffer)[1]);
                                        if ((flags & 0x8000)) {
                                                sendto(sock, buffer, r, MSG_NOSIGNAL, (struct sockaddr*) &sender, sl);
                                        }
                                }

                                close(socks_to_send);

                                exit(0);
                        }
                } else {
                        // we want to make them go away
                        uint16_t * psr = (uint16_t*) buffer;
                        //  psr[0] is the transaction ID
                        psr[1] = 0x8100; // if we wanted, we could set this to be 0x8103, to say "no such name" - but then if there's an AAAA query as well, that will cancel out an A query.
                        // send the packet back at them.
                        sendto(sock, buffer, r, MSG_NOSIGNAL, (struct sockaddr*) &sender, sl);
                }
        }
        return;
}

int main(int argc, char *argv[])
{
        int inotifyfd = 0;
        int c = 0;
        while ((c = getopt(argc, argv, "r4h:")) != -1) {
                switch (c) {
                case 'h':
                        hostname_override = optarg;
                        break;
                case 'r':
                        resolver = socket(AF_INET, SOCK_DGRAM, 0);
                        break;
                case '4':
                        is_ipv4_only = 1;
                        break;
                default:
                case '?':
                        fprintf(stderr, "error: usage: " PACKAGE_NAME " [-r] [-h hostname override]\n");
                        exit(1);
                }
        }

        sin_multicast.sin_port = htons(MDNS_PORT);

        initialize_hostname();

        inotifyfd = inotify_init1(IN_NONBLOCK);

        if (!hostname_override) {
                hostname_watch = inotify_add_watch(inotifyfd, "/etc/hostname", IN_MODIFY | IN_CREATE);
                if (hostname_watch < 0) {
                        fprintf(stderr, "warning: inotify cannot watch file\n");
                }
        }

        if (resolver < 0) {
                fprintf(stderr, "error: resolver requested but unavailable\n");
                exit(1);
        }

        if (resolver) {
                // the resolver uses child processes.  to clean up zombies, we catch SIGCHILD.
                //signal( SIGCHLD, &ChildProcessComplete );

                int optval = 1;
                if (setsockopt(resolver, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof( optval)) != 0) {
                        fprintf(stderr, "warning: could not set SO_REUSEPORT on resolver\n");
                        exit(1);
                }

                struct sockaddr_in sin_resolve = {
                        .sin_family = AF_INET,
                        .sin_addr =
                        { inet_addr(RESOLVER_IP)},
                        .sin_port = htons(RESOLVER_PORT)
                };

                if (bind(resolver, (struct sockaddr *) &sin_resolve, sizeof(sin_resolve)) == -1) {
                        fprintf(stderr, "error: could not bind to IPv4 MDNS port (%d %s)\n", errno, strerror(errno));
                        exit(1);
                }

                printf("resolver configured on \"%s\"\n", RESOLVER_IP);
        }

#if (DISABLE_IPV6 == 0)
        if (!is_ipv4_only) {
                sdsock = socket(AF_INET6, SOCK_DGRAM, 0);
                if (sdsock < 0) {
                        fprintf(stderr, "warning: opening IPv6 datagram socket error,  trying IPv4");
                        sdsock = socket(AF_INET, SOCK_DGRAM, 0);
                        is_bound_6 = 0;
                } else {
                        is_bound_6 = 1;
                }
        } else {
#endif
                sdsock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sdsock < 0) {
                        fprintf(stderr, "error: could not open IPv4 Socket\n");
                }
#if (DISABLE_IPV6 == 0)
        }
#endif

        /* not just avahi, but other services, too will bind to udp/53, but we can
         * use SO_REUSEPORT to allow multiple people to bind simultaneously, but
         * all binds (event theirs) must use set opt SO_REUSEPORT */
        int optval = 1;
        if (setsockopt(sdsock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof( optval)) != 0) {
                fprintf(stderr, "warning: could not set SO_REUSEPORT\n");
        }

        if (setsockopt(sdsock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval)) != 0) {
                fprintf(stderr, "warning: could not set SO_REUSEADDR\n");
        }

        /* we have to enable PKTINFO so we can use recvmsg, so we can get desination
         * address so we can reply accordingly */
        if (setsockopt(sdsock, IPPROTO_IP, IP_PKTINFO, &optval, sizeof( optval)) != 0) {
                fprintf(stderr, "error: kernel version must be greater than 2.6.14 "
                                "to support IP_PKTINFO on a socket\n");
                exit(1);
        }

#if (DISABLE_IPV6 == 0)
        if (is_bound_6 && setsockopt(sdsock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof( optval)) != 0) {
                fprintf(stderr, "error: kernel version must be greater than 2.6.14 "
                                "to support IPV6_RECVPKTINFO on IPv6 socket\n");
                exit(1);
        }
#endif

        sdifaceupdown = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

        if (sdifaceupdown < 0) {
                fprintf(stderr, "warning: couldn't open socket for monitoring address changes\n");
        } else {
                // bind looking for interface changes
                struct sockaddr_nl addr;
                memset(&addr, 0, sizeof(addr));
                addr.nl_family = AF_NETLINK;
                addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
                if (bind(sdifaceupdown, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
                        fprintf(stderr, "warning: couldn't bind looking for address changes\n");
                        close(sdifaceupdown);
                        sdifaceupdown = -1;
                }
        }

        // bind the normal MDNS socket
#if (DISABLE_IPV6 == 0)
        if (is_bound_6) {
                struct sockaddr_in6 sin6 = {
                        .sin6_family = AF_INET6,
                        .sin6_addr = IN6ADDR_ANY_INIT,
                        .sin6_port = htons(MDNS_PORT)
                };
                if (bind(sdsock, (struct sockaddr *) &sin6, sizeof(sin6)) == -1) {
                        fprintf(stderr, "error: could not bind to IPv6 MDNS port (%d %s)\n", errno, strerror(errno));
                        exit(1);
                }
        } else
#endif
        {
                struct sockaddr_in sin = {
                        .sin_family = AF_INET,
                        .sin_addr =
                        { INADDR_ANY},
                        .sin_port = htons(MDNS_PORT)
                };
                if (bind(sdsock, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
                        fprintf(stderr, "error: could not bind to IPv4 MDNS port (%d %s)\n", errno, strerror(errno));
                        exit(1);
                }
        }

        int r = 0;
        do {
                int failcount = 0;
                r = request_interfaces();
                if (r != 0) {
                        if (failcount++ > 10) {
                                fprintf(stderr, "error: too many failures getting interfaces\n");
                                return -9;
                        }
                        usleep((1000000/1000)*1);
                }
        } while (r != 0);

        while (1) {
                struct pollfd fds[4] = {
                        { .fd = sdsock, .events = POLLIN | POLLHUP | POLLERR, .revents = 0},
                        { .fd = sdifaceupdown, .events = POLLIN | POLLHUP | POLLERR, .revents = 0},
                        { .fd = inotifyfd, .events = POLLIN, .revents = 0},
                        { .fd = resolver, .events = POLLIN | POLLHUP | POLLERR, .revents = 0},
                };

                int polls = resolver ? 4 : 3;

                // Make poll wait for literally forever.
                r = poll(fds, polls, -1);

                //printf( "%d: %d / %d / %d / %d\n", r, fds[0].revents, fds[1].revents, fds[2].revents, fds[3].revents );

                if (r < 0) {
                        fprintf(stderr, "error: poll = %d failed (%d %s)\n",
                                r, errno, strerror(errno));
                        exit(1);
                }

                if (fds[0].revents) {
                        if (fds[0].revents & POLLIN) {
                                handle_message_recv(sdsock, 0);
                        }

                        if (fds[0].revents & (POLLHUP | POLLERR)) {
                                fprintf(stderr, "error: IPv6 socket experienced fault\n");
                                exit(1);
                        }
                }

                if (fds[1].revents) {
                        if (fds[1].revents & POLLIN) {
                                handle_netlink_recv();
                        }
                        if (fds[1].revents & (POLLHUP | POLLERR)) {
                                fprintf(stderr, "error: NETLINK socket experienced fault\n");
                                exit(1);
                        }
                }

                if (fds[2].revents) {
                        struct inotify_event event;
                        int r = read(inotifyfd, &event, sizeof( event));
                        r = r;
                        initialize_hostname();
                }

                if (fds[3].revents) {
                        if (fds[3].revents & POLLIN) {
                                handle_message_recv(resolver, 1);
                        }

                        if (fds[3].revents & (POLLHUP | POLLERR)) {
                                fprintf(stderr, "error: resolver socket experienced fault\n");
                                exit(1);
                        }
                }

                /* todo maybe cleanup any remaining zombie processes from resolver,
                 * this could also be done in a SIGCHLD signal handler, but that
                 * would interrupt the poll */
                if (resolver) {
                        int wstat;
                        wait3(&wstat, WNOHANG, NULL);
                }
        }

        exit(0);
}
