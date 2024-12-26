//
// MIT License
//
// Copyright 2024 Charles Lohr
// Copyright 2025 Michael Miller
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
#include <ctype.h>
#include <stdarg.h>

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

#define MDNS_BRD_ADDR ((in_addr_t) 0xfb0000e0)  // 224.0.0.251

/**
 * @brief common DNS record types
 */
#define DNS_TYPE_A              1       /**< ip4 host address */
#define DNS_TYPE_AAAA           28      /**< ip6 host address */
#define DNS_TYPE_ALL            255     /**< all available data */
#define DNS_TYPE_TEXT           16      /**< a text string */
#define DNS_TYPE_NS             2       /**< a nameserver */
#define DNS_TYPE_CNAME          5       /**< a CNAME (alias) */
#define DNS_TYPE_MX             15      /**< a mail exchange  */
#define DNS_TYPE_PTR            12      /**< a PTR (pointer) record */
#define DNS_TYPE_HINFO          13      /**< Host info */

/**
 * @brief a union for DNS flags
 */
typedef union __attribute__((packed, aligned(1))){
        struct {
                uint16_t rcode : 4; /**< response code (4 bits) */
                uint16_t cd : 1; /**< non auth data (1 bit) */
                uint16_t ad : 1; /**< answer authenticated (1 bit) */
                uint16_t z : 1; /**< Z reserved (1 bit) */
                uint16_t ra : 1; /**< recursion available (1 bit) */
                uint16_t rd : 1; /**< recursion desired (1 bit) */
                uint16_t tc : 1; /**< truncated message (1 bit) */
                uint16_t aa : 1; /**< authoritative answer (1 bit) */
                uint16_t opcode : 4; /**< operation code (4 bits) */
                uint16_t qr : 1; /**< query/response (1 bit) */
        }
        bits; /**< bit-field representation for individual access */
        uint16_t v; /**< full 16-bit representation of the DNS flags*/
} flags_t;

/**
 * @brief the mDNS query type
 */
typedef struct __attribute__ ((packed,aligned(1))) {
        uint16_t transaction_id; /**< unique transaction ID for the query */
        flags_t flags; /**< flags (e.g., query/response, authoritative) */
        uint16_t question_count; /**< number of questions */
        uint16_t answer_count; /**< number of answers (if any, typically 0 for queries)*/
        uint16_t authority_count; /**< number of authority records*/
        uint16_t additional_count; /**< number of additional records */
} mdns_header_t;

typedef struct _qu_t {
        mdns_header_t *hdr; /**< pointer to the original header */
        uint16_t record_type; /**< record type yanked from the question */
        uint16_t record_class; /**< class type yanked from the question */
        int ip_proto;/**< ipv4/6 protocol selector yanked from the recv */
        char name[256];/**< the stringified name assembled from labels of the question */
        uint8_t *name_ptr;/**< pointer to the base of dns labels of the question */
        int name_ptr_len;/**< total number of bytes of comprising all labels */
}qu_t; /**< question response complex argument */

static const char *hostname_override;
static char hostname[HOST_NAME_MAX + 1] = {0};
static int hostnamelen = 0;
static int hostname_watch = 0;
static int sdsock = 0;
static int is_ipv4_only = 0;
static int is_bound_6 = 0;
static int sdifaceupdown = 0;
static int resolver = 0;
static int g_verbose = 0;

// for multicast queries, and multicast replies.
struct sockaddr_in sin_multicast = {
        .sin_family = AF_INET,
        .sin_addr = {MDNS_BRD_ADDR},
        .sin_port = 0
};

/**
 * @brief a verbosity flag controlled path to stdout
 *
 * @param fmt
 * @param ...
 */
void applogf(const char *fmt, ...)
{
        int rs = 0;
        va_list ap = {0};
        char *buf = NULL;

        if (!g_verbose) {
                return;
        }

        va_start(ap, fmt);
        rs = vasprintf(&buf, fmt, ap);
        va_end(ap);

        if (rs > 0) {
                printf("%s", buf);
        }

        free(buf);
}
/**
 * @brief validate a Linux hostname by RFC 1123
 *
 * @param hostname pointer to string of interest
 *
 * @return non zero if valid, zero otherwise
 */
static int is_valid_hostname(const char *hostname)
{
        int label_length = 0;
        int length = 0;
        int i = 0;
        char c = 0;

        /* check if hostname is null or empty */
        if (hostname == NULL || *hostname == '\0') {
                return 0;
        }

        /* length validation */
        length = strlen(hostname);
        if (length > 255) {
                return 0;
        }

        label_length = 0;

        for (i = 0; i < length; ++i) {
                c = hostname[i];
                /* check for valid characters (alphanumeric, '.', or '-') */
                if (!(isalnum(c) || c == '.' || c == '-')) {
                        return 0;
                }

                /* handle periods */
                if (c == '.') {
                        /* a label must not be empty or too long */
                        if (label_length == 0 || label_length > 63) {
                                return 0;
                        }
                        label_length = 0; /* Reset for next label */
                } else {
                        /* handle start or end with a dash */
                        if (c == '-' && (i == 0 || hostname[i - 1] == '.' || i == length - 1)) {
                                return 0;
                        }
                        label_length++;
                }
        }

        /* final label validation */
        if (label_length == 0 || label_length > 63) {
                return 0;
        }

        return 1; /* Valid */
}

/**
 * @brief it reads default system path /etc/hostname and attempts to use name
 *        provided as the name we listen listen and match with
 *
 *        note the name/match can be over-ridden by command line option
 */
static int initialize_hostname()
{
        int j = 0;
        int read_sz = 0;
        int fd = 0;

        if (hostname_override) {
                hostnamelen = strlen(hostname_override);
                strncpy(hostname, hostname_override, sizeof(hostname)-1);
                goto validate;
        }

        if ((fd = open("/etc/hostname", O_RDONLY)) < 1) {
                goto hostnamefault;
        }

        read_sz = read(fd, hostname, HOST_NAME_MAX);

        close(fd);

        if (read_sz <= 0) {
                goto hostnamefault;
        }

        hostnamelen = read_sz;

        for (j = 0; j < read_sz; j++) {
                char c = hostname[j];
                if (c == '\n') { // truncate at newline
                        hostnamelen = j;
                } else if (c >= 'A' && c <= 'Z') { // convert to lowercase
                        hostname[j] = c + 'z' - 'Z';
                }
        }

        hostname[hostnamelen] = 0;

validate:

        if (!is_valid_hostname(hostname)) {
                fprintf(stderr,"error:  hostname %s is not RFC 1123 compliant\n", hostname);
                return 0;
        }

        printf("responding to hostname: \"%s.local\"\n", hostname);

        return 1;

hostnamefault:

        fprintf(stderr, "error: can't stat /etc/hostname\n");

        return 0;
}

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

        if (setsockopt(sdsock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char*)&mreq6,
                        sizeof(mreq6)) == -1) {
                fprintf(stderr, "warning: could not join ipv6 membership on "
                        "interface %d (%d %s)\n", interface, errno, strerror(errno));
        }
}

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

        if (setsockopt(sdsock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq,
                        sizeof(mreq)) == -1) {
                char *addr = inet_ntoa(*saddr);
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
                struct sockaddr_in *sa4 = (struct sockaddr_in*)addr;
                const char * addrout = inet_ntop(family, &sa4->sin_addr, addrbuff, sizeof(addrbuff) - 1);
                if (!(is_ipv4_local(&sa4->sin_addr))) {
                        return;
                }
                printf("multicast adding address: (%s)\n", addrout);
                multicast_addr_add(&sa4->sin_addr);
        } else if (family == AF_INET6 && !is_ipv4_only) {
                char addrbuff[INET6_ADDRSTRLEN + 1] = {0};
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
                const char * addrout = inet_ntop(family, &sa6->sin6_addr, addrbuff, sizeof(addrbuff) - 1);
                if (!(is_ipv6_local(&sa6->sin6_addr))){
                        return;
                }
                printf("multicast adding interface: %u (%s)\n", sa6->sin6_scope_id, addrout);
                multicast_addr_add6(sa6->sin6_scope_id);
        }
        return;
}

/**
 * @brief it loops through our interface list and passes ifs to the multicast add
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
                                                        multicast_addr_check((struct sockaddr*)&sai);
                                                } else if (ifa->ifa_family == AF_INET6) {
                                                        int ifindex = ifa->ifa_index;
                                                        struct sockaddr_in6 sai = {0};
                                                        sai.sin6_family = AF_INET6;
                                                        sai.sin6_scope_id = ifindex;
                                                        memcpy(&sai.sin6_addr, RTA_DATA(rth), pld);
                                                        multicast_addr_check((struct sockaddr*)&sai);
                                                }
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
 * @brief extract and concatenate labels of a question with a '.' and then
 *        terminate with '.local'
 *
 * @param baseptr pointer to the start of the name or array of labels
 * @param eptr end pointer of the data section of the query
 * @param name_str pointer to buffer to hold rendered labels
 * @param len total length of computed name_str
 *
 * @return baseptr address incremented by the length of labels consumed
 */
uint8_t * mdns_path_parse(uint8_t *baseptr, uint8_t *eptr, char *name_str, int *len)
{
        int l = 0;
        int j = 0;
        *len = 0;

        while (baseptr != eptr) {

                // see how long the label we should read is
                l = *(baseptr++);

                // zero-length strings indicate no more labels are to be read
                if (l == 0) {
                        break;
                }

                if (*len + l >= MAX_MDNS_PATH) {
                        return NULL;
                }

                // if not the first label, append a '.'
                if (*len != 0) {
                        *(name_str++) = '.';
                        (*len)++;
                }

                // assure the label is lower case a-z
                for (j = 0; j < l; j++) {
                        if (baseptr[j] >= 'A' && baseptr[j] <= 'Z') {
                                name_str[j] = baseptr[j] - 'A' + 'a';
                        } else {
                                name_str[j] = baseptr[j];
                        }
                }

                // move along in the data to check if there are more labels to concatenate
                name_str += l;
                baseptr += l;
                *len += l;
        }

        *name_str = 0;

        return baseptr;
}

/**
 * @brief take attributes of the mDNS header to network byte order
 *
 * @param hdr
 */
static void mdns_swap_to_net(mdns_header_t *hdr)
{
        hdr->transaction_id = htons(hdr->transaction_id);
        hdr->flags.v = htons(hdr->flags.v);
        hdr->question_count = htons(hdr->question_count);
        hdr->answer_count = htons(hdr->answer_count);
        hdr->authority_count = htons(hdr->authority_count);
        hdr->additional_count = htons(hdr->additional_count);
}

/**
 * @brief take attributes of the mDNS header to host byte order
 *
 * @param hdr
 */
static void mdns_swap_to_host(mdns_header_t *hdr)
{
        hdr->transaction_id = ntohs(hdr->transaction_id);
        hdr->flags.v = ntohs(hdr->flags.v);
        hdr->question_count = ntohs(hdr->question_count);
        hdr->answer_count = ntohs(hdr->answer_count);
        hdr->authority_count = ntohs(hdr->authority_count);
        hdr->additional_count = ntohs(hdr->additional_count);
}

/**
 * @brief fabricate a response to request that matched our name
 *
 * @param sock
 * @param sender
 * @param sender_len
 * @param qu
 * @param in_any
 */
static void respond(int sock, struct sockaddr_in6 *sender, int sender_len, qu_t *qu, void *in_any)
{
        uint8_t outbuff[2048] = {0}; /**< large enough to hold a single datagram */
        uint8_t *obptr = outbuff;
        mdns_header_t *rsp = (mdns_header_t*)outbuff;
        struct in_addr *local_addr_4 = in_any;
        struct in6_addr *local_addr_6 = in_any;

        int sendA = ((qu->record_type == DNS_TYPE_A) && qu->ip_proto == IPPROTO_IP);
        int sendAAAA = ((qu->record_type == DNS_TYPE_AAAA) && qu->ip_proto == IPPROTO_IPV6);

        if (!sendA && !sendAAAA) {
                return;
        }

        // for ipv4/6 responses we always have this in common
        rsp->transaction_id = qu->hdr->transaction_id;

        // setup the flags field as required
        rsp->flags.bits.qr = 1;
        rsp->flags.bits.aa = 1;

        rsp->question_count = 0;
        rsp->answer_count = 1;
        rsp->authority_count = 0;
        rsp->additional_count = 0;

        mdns_swap_to_net(rsp);

        obptr += sizeof(mdns_header_t);

        // fabricate the 'Answer'
        memcpy(obptr, qu->name_ptr, qu->name_ptr_len + 1);
        obptr += qu->name_ptr_len + 1;
        *(obptr++) = 0;
        *(obptr++) = 0x00;
        *(obptr++) = (sendA ? 0x01 : 0x1c); // A record
        *(obptr++) = 0x80;
        *(obptr++) = 0x01; // flush cache + in ptr.
        *(obptr++) = 0x00;
        *(obptr++) = 0x00; // TTL
        *(obptr++) = 0x00;
        *(obptr++) = 240; // 240 seconds (4 minutes)

        // but if ipv4
        if (sendA) {
                *(obptr++) = 0x00;
                *(obptr++) = 0x04; // Size 4 (IP)
                memcpy(obptr, &local_addr_4->s_addr, 4);
                obptr += 4;
        } else if (sendAAAA) { // else ipv6
                *(obptr++) = 0x00;
                *(obptr++) = 0x10; // Size 16 (IPv6)
                memcpy(obptr, &local_addr_6->s6_addr, 16);
                obptr += 16;
        }

        /* 6762 5.4 Multicast DNS defines the top bit in the class field of a
         * DNS question as the unicast-response bit */

        // query is requesting a unicast response
        if (qu->record_class & 0x8000) {
                if (sendto(sock, outbuff, obptr - outbuff, MSG_NOSIGNAL,
                        (struct sockaddr*)sender, sender_len) != obptr - outbuff) {
                        fprintf(stderr,
                                "warning: could not send unicast reply\n");
                }
                return;
        }

        // per spec, we default to sending a multicast response
        int loopbackEnable = 0;
        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loopbackEnable, sizeof(loopbackEnable)) < 0) {
                fprintf(stderr, "warning: cannot prevent self-looping of mDNS packets\n");
                return;
        }

        if (sendto(sock, outbuff, obptr - outbuff, MSG_NOSIGNAL,
                (struct sockaddr*) &sin_multicast, sizeof(sin_multicast)) != obptr - outbuff) {
                fprintf(stderr, "warning: could not send multicast reply\n");
        }
}

/**
 * @brief compute the length of the name up to the first dot, note that this
 *        method expects the name to be null terminated and may run out of
 *        bounds otherwise
 *
 * @param name
 *
 * @return computed length or zero if undetermined
 */
int dotlen_compute(const char *name)
{
        int dotlen = 0;
        const char *cpp = name;

        while (*cpp && *cpp != '.') {
                cpp++;
        }

        if (*cpp == '.') {
                dotlen = (cpp + 1) - name - 1;
        }

        return dotlen;
}

static void handle_message_recv(int sock, int is_resolver)
{
        uint8_t buffer[9036] = {0}; // per RFC-6762 Section 6.1
        uint16_t c = 0;
        uint8_t cmbuf[1024] = {0};
        struct in_addr local_addr_4 = {0};
        void *in_any = NULL;
        struct cmsghdr *cmsg = NULL;
        struct in6_addr local_addr_6 = {0};
        struct sockaddr_in6 sender = {0};
        socklen_t sender_len = sizeof(sender);
        qu_t qu = {0};

        /* using recvmsg, this is a little tricky, to avoid having a separate
         * socket for every single interface, we can instead, just recvmsg and
         * discern which interface the message originated */

        // note: if you want access to the data you need to init the msg_iovec fields
        struct iovec iov = {
                .iov_base = buffer,
                .iov_len = sizeof(buffer),
        };

        struct msghdr msghdr = {
                .msg_name = &sender,
                .msg_namelen = sizeof(sender),
                .msg_control = cmbuf,
                .msg_controllen = sizeof(cmbuf),
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

        qu.ip_proto = -1;

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
                        qu.ip_proto = IPPROTO_IP;
                } else if (cmsg->cmsg_level == IPPROTO_IPV6) {
                        // note: some build platforms do not include this.
                        struct in6_pktinfo_shadow {
                                struct in6_addr ipi6_addr; /* src/dst IPv6 address */
                                unsigned int ipi6_ifindex; /* send/recv interface index */
                        };
                        struct in6_pktinfo_shadow * pi = (struct in6_pktinfo_shadow *) CMSG_DATA(cmsg);
                        local_addr_6 = pi->ipi6_addr;
                        in_any = &pi->ipi6_addr;
                        qu.ip_proto = IPPROTO_IPV6;
                }
        }

        if (!in_any || qu.ip_proto == -1) {
                fprintf(stderr, "error: no ipv4/6 address set\n");
                return; // insufficient source address info
        }

        qu.hdr = (mdns_header_t*)buffer;

        mdns_swap_to_host(qu.hdr);

        // mDNS reply (we are a server, not a client, so discard answers)
        if (qu.hdr->flags.bits.qr) {
                return;
        }

        applogf("\n\n");
        applogf("  question_count: %d\n", qu.hdr->question_count);
        applogf("    answer_count: %d\n", qu.hdr->answer_count);
        applogf(" authority_count: %d\n", qu.hdr->authority_count);
        applogf("additional_count: %d\n", qu.hdr->additional_count);

        uint8_t *dataptr = buffer + sizeof(mdns_header_t);
        uint8_t *dataend = dataptr + r - sizeof(mdns_header_t);

        int is_a_suitable_mdns_record_query = 0;
        int found = 0;
        int pathlen = 0;
        int dotlen = 0;

        qu.name_ptr = dataptr;

        // disect the query questions section
        for (c = 0; ((dataend - dataptr) > 0) && (c < qu.hdr->question_count) ; c++) {
                qu.record_type = 0;
                qu.record_class = 0;
                pathlen = 0;
                memset(qu.name, 0x00, sizeof(qu.name));

                qu.name_ptr = dataptr;

                applogf("question: %d datalen %ld\n", c, (dataend - dataptr));

                // work our way through the question and extract the labels into a name
                if (!(dataptr = mdns_path_parse(dataptr, dataend, qu.name, &qu.name_ptr_len))){
                        break; // we're done
                }

                // make sure there is still room left for the rest of the record
                if ((dataend - dataptr) < 4) {
                        applogf("question is (%ld bytes) short of type and class values\n",
                                (dataend - dataptr));
                        break;
                }

                /* at this point, path is set, the next 4 bytes/2 shorts should
                 * be the record type and class */
                qu.record_type = (dataptr[0]<< 8) | dataptr[1];
                dataptr += sizeof(uint16_t);

                // record class
                qu.record_class = (dataptr[0]<<8) | dataptr[1];
                dataptr += sizeof(uint16_t);

                if ((qu.record_class & 0x7fff) != 0x0001) {
                        // note: some apple stuff
                        applogf("bad [%s] class %04x\n", qu.name, qu.record_class);
                        continue;
                }

                /* todo: handle type 12 (ptr/domain name pointer) to take our
                 * interface numbers back to a name */

                // check for type 1 (host address)
                if ((qu.record_type == DNS_TYPE_A)
                        || (!is_ipv4_only && (qu.record_type == DNS_TYPE_AAAA))) {
                        is_a_suitable_mdns_record_query = 1;
                }

                pathlen = strlen(qu.name);
                if (pathlen < 6 || strcmp(qu.name + pathlen - 6, ".local") != 0) {
                        applogf("path [%s] does not end in .local\n", qu.name);
                        continue;
                }

                if ( ( (dotlen = dotlen_compute(qu.name)) == hostnamelen)
                        && (memcmp(hostname, qu.name, dotlen) == 0)) {
                        applogf("match hostname [%s] == [%s]\n", hostname, qu.name);
                        respond(sock, &sender, sender_len,
                                &qu,
                                in_any);
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
                                        fprintf(stderr, "error: could not create multicast message\n");
                                        exit(1);
                                }

                                int loopbackEnable = 0;
                                if (setsockopt(socks_to_send, IPPROTO_IP, IP_MULTICAST_LOOP, &loopbackEnable, sizeof(loopbackEnable)) < 0) {
                                        fprintf(stderr, "error: cannot prevent self-looping of mDNS packets\n");
                                        exit(1);
                                }

                                struct timeval tv = {.tv_sec = 3};
                                if (setsockopt(socks_to_send, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
                                        fprintf(stderr, "error: could not set sock option on repeated socket\n");
                                        close(socks_to_send);
                                        exit(1);
                                }

                                if (sendto(socks_to_send, buffer, r, MSG_NOSIGNAL, (struct sockaddr*)&sin_multicast, sizeof(sin_multicast)) < 0) {
                                        fprintf(stderr, "error: could not repeat as mDNS request\n");
                                        close(socks_to_send);
                                        exit(1);
                                }

                                for (;;) {
                                        r = recv(socks_to_send, buffer, sizeof(buffer), 0);
                                        if (r <= 0) {
                                                break;
                                        }
                                        // If the packet is a reply, not a question, we can forward it back to the asker.
                                        uint16_t flags = ntohs(((uint16_t*)buffer)[1]);
                                        if ((flags & 0x8000)) {
                                                sendto(sock, buffer, r, MSG_NOSIGNAL, (struct sockaddr*)&sender, sender_len);
                                        }
                                }

                                close(socks_to_send);

                                exit(0);
                        }
                } else {
                        // we want to make them go away
                        uint16_t * psr = (uint16_t*)buffer;
                        //  psr[0] is the transaction ID
                        psr[1] = 0x8100; // if we wanted, we could set this to be 0x8103, to say "no such name" - but then if there's an AAAA query as well, that will cancel out an A query.
                        // send the packet back at them.
                        sendto(sock, buffer, r, MSG_NOSIGNAL, (struct sockaddr*)&sender, sender_len);
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
                case 'v':
                        g_verbose++;
                        applogf("verbosity: %d\n", g_verbose);
                        break;;
                default:
                case '?':
                        fprintf(stderr, "error: usage: " PACKAGE_NAME " [-r] [-h hostname override]\n");
                        exit(1);
                }
        }

        sin_multicast.sin_port = htons(MDNS_PORT);

        if (!initialize_hostname()) {
                fprintf(stderr, "error: hostname initialization failed\n");
                exit(1);
        }

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
                        .sin_addr = { inet_addr(RESOLVER_IP)},
                        .sin_port = htons(RESOLVER_PORT)
                };

                if (bind(resolver, (struct sockaddr *) &sin_resolve, sizeof(sin_resolve)) == -1) {
                        fprintf(stderr, "error: could not bind to IPv4 MDNS port (%d %s)\n", errno, strerror(errno));
                        exit(1);
                }

                printf("resolver configured on \"%s\"\n", RESOLVER_IP);
        }

        if (!is_ipv4_only) {
                sdsock = socket(AF_INET6, SOCK_DGRAM, 0);
                if (sdsock < 0) {
                        fprintf(stderr, "warning: opening IPv6 datagram socket error, trying IPv4");
                        sdsock = socket(AF_INET, SOCK_DGRAM, 0);
                        is_bound_6 = 0;
                } else {
                        is_bound_6 = 1;
                }
        } else {
                sdsock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sdsock < 0) {
                        fprintf(stderr, "error: could not open IPv4 Socket\n");
                }

        }


        /* not just avahi, but other services, too will bind to udp/53, but we can
         * use SO_REUSEPORT to allow multiple people to bind simultaneously, but
         * all binds (even theirs) must set opt SO_REUSEPORT */
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

        if (is_bound_6 && setsockopt(sdsock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof( optval)) != 0) {
                fprintf(stderr, "error: kernel version must be greater than 2.6.14 "
                                "to support IPV6_RECVPKTINFO on IPv6 socket\n");
                exit(1);
        }

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
        if (is_bound_6) {
                struct sockaddr_in6 sin6 = {
                        .sin6_family = AF_INET6,
                        .sin6_addr = IN6ADDR_ANY_INIT,
                        .sin6_port = htons(MDNS_PORT)
                };
                if (bind(sdsock, (struct sockaddr *)&sin6, sizeof(sin6)) == -1) {
                        fprintf(stderr, "error: could not bind to IPv6 mDNS port (%d %s)\n", errno, strerror(errno));
                        exit(1);
                }
        } else {
                struct sockaddr_in sin = {
                        .sin_family = AF_INET,
                        .sin_addr = {INADDR_ANY},
                        .sin_port = htons(MDNS_PORT)
                };
                if (bind(sdsock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
                        fprintf(stderr, "error: could not bind to IPv4 mDNS port (%d %s)\n", errno, strerror(errno));
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
