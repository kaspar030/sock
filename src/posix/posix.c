#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <stdio.h>

#include "net/sock/udp.h"

#define SOCK_UDP_LOCAL (0x1)
#define SOCK_UDP_REMOTE (0x2)

#define SOCK_NO_TIMEOUT (UINT32_MAX)

static int _bind_to_device(int fd, unsigned netif);
static int _set_remote(sock_udp_t *sock, const sock_udp_ep_t *dst);

int ipv6_addr_is_multicast(uint8_t addr[16])
{
    return *addr == 0xFF;
}

int ipv6_addr_is_unspecified(const uint8_t addr[16])
{
    return memcmp(addr, &in6addr_any, 16) == 0;
}

static int _addrlen(unsigned family) {
    return ((family == AF_INET6) || (family == 0)) ?
        sizeof(sockaddr_t) : sizeof(struct sockaddr_in);
}

static int _endpoint_to_sockaddr(void *sockaddr, const sock_udp_ep_t *endpoint)
{
    assert(sockaddr);
    assert(endpoint);

    switch(endpoint->family) {
#if defined(SOCK_HAS_IPV4)
        case AF_INET:
            {
                struct sockaddr_in *dst_addr = sockaddr;
                dst_addr->sin_family = AF_INET;
                dst_addr->sin_port = htons(endpoint->port);
                if (endpoint->addr.ipv4) {
                    memcpy(&dst_addr->sin_addr.s_addr, endpoint->addr.ipv4, 4);
                }
                else {
                    dst_addr->sin_addr.s_addr = INADDR_ANY;
                }
                return 0;
            }
#endif
#if defined(SOCK_HAS_IPV6)
        case 0:
        case AF_INET6:
            {
                sockaddr_t *dst_addr6 = /*(sockaddr_t *)*/ sockaddr;
                dst_addr6->sin6_family = AF_INET6;
                if (!ipv6_addr_is_unspecified(endpoint->addr.ipv6)) {
                    memcpy(&dst_addr6->sin6_addr, endpoint->addr.ipv6, 16);
                }
                else {
                    dst_addr6->sin6_addr = in6addr_any;
                }
                dst_addr6->sin6_port = htons(endpoint->port);
                dst_addr6->sin6_scope_id = endpoint->netif;
                return 0;
            }
#endif
        default:
            return -EINVAL;
    }
}

static int _sockaddr_to_endpoint(sock_udp_ep_t *endpoint, void *_sockaddr)
{
    assert(_sockaddr);
    assert(endpoint);

    struct sockaddr *sockaddr = _sockaddr;
    switch(sockaddr->sa_family) {
#if defined(SOCK_HAS_IPV4)
        case AF_INET:
            {
                struct sockaddr_in *addr = (struct sockaddr_in*) sockaddr;
                endpoint->family = AF_INET;
                endpoint->port = ntohs(addr->sin_port);
                memcpy(endpoint->addr.ipv4, &addr->sin_addr.s_addr, 4);
                return 0;
            }
#endif
#if defined(SOCK_HAS_IPV6)
        case AF_INET6:
            {
                sockaddr_t *addr = (sockaddr_t*) sockaddr;
                endpoint->family = AF_INET6;
                endpoint->port = ntohs(addr->sin6_port);
                endpoint->netif = addr->sin6_scope_id;
                memcpy(endpoint->addr.ipv6, &addr->sin6_addr, 16);
                return 0;
            }
#endif
        default:
            return -EINVAL;
    }
}

int _udp_connect_possible(const sock_udp_ep_t *remote)
{
    if (remote->family == AF_INET) {
        if (remote->addr.ipv4_u32 == 0xFFFFFFFF) {
            return 0;
        }
    }
    return 1;
}

int sock_udp_create(sock_udp_t *sock, const sock_udp_ep_t *local, const sock_udp_ep_t *remote, uint16_t flags)
{
    (void)flags;
    memset(sock, 0, sizeof(sock_udp_t));

    int res;
    sockaddr_t local_addr;
    sockaddr_t remote_addr;

    if (!(local || remote)) {
        return -EINVAL;
    }

    if ((local && remote) && (local->family != remote->family)) {
        return -EINVAL;
    }

    if (local) {
        sock->family = local->family;
    }
    else {
        sock->family = remote->family;
    }

#if defined(SOCK_HAS_IPV6)
    if (!sock->family) {
        sock->family = AF_INET6;
    }
#endif

    sock->fd = socket(sock->family, SOCK_DGRAM, IPPROTO_IP);
    if (sock->fd == -1) {
        perror("creating socket");
        return -1;
    }

    if (local) {
        sock->family = local->family;

        memset((void*)&local_addr, '\0', sizeof(local_addr));
        _endpoint_to_sockaddr(&local_addr, local);

        if (!remote || (!_udp_connect_possible(remote))) {
            unsigned addr_len = _addrlen(sock->family);

            const int on=1;
            setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
            setsockopt(sock->fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));

#if defined(SOCK_HAS_IPV6)
            int ipv6_v6only = 0;
            switch(sock->family) {
                case AF_INET6:
                    ipv6_v6only = 1;
                case 0:
                    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_v6only, sizeof(ipv6_v6only));
            }
#endif

            if (bind(sock->fd, (struct sockaddr *)&local_addr, addr_len) == -1) {
                res = -1;
                perror("bind");
                goto close;
            }
            sock->flags |= SOCK_UDP_LOCAL;
        }
    }

    if (remote) {
        memset((void*)&remote_addr, '\0', sizeof(remote_addr));
        _endpoint_to_sockaddr(&remote_addr, remote);
        unsigned addr_len = _addrlen(sock->family);

        if (!local) {
            sock->family = remote->family;
        }

        if (_udp_connect_possible(remote)) {
            if ((connect(sock->fd, (struct sockaddr *)&remote_addr, addr_len)) == -1 ) {
                res = -1;
                perror("connect");
                goto close;
            }
        }

        if ((res = _set_remote(sock, remote))) {
            goto close;
        }
        sock->flags |= SOCK_UDP_LOCAL;
    }

    return 0;

close:
    close(sock->fd);

    return res;
}

void sock_udp_close(sock_udp_t *sock)
{
    if (sock && sock->fd) {
        close(sock->fd);
    }
}

static int _bind_to_device(int fd, unsigned netif)
{
    struct ifreq ifr;
    memset(&ifr, '\0', sizeof(ifr));

    if (netif) {
        ifr.ifr_ifindex = netif;
        if (ioctl(fd, SIOCGIFNAME, &ifr)==-1) {
            puts("error getting ifname");
            return -1;
        }
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                (void *)&ifr, sizeof(ifr)) < 0) {
        perror("error setting SO_BINDTODEVICE");
        return -1;
    }

    return 0;
}

static int _set_remote(sock_udp_t *sock, const sock_udp_ep_t *dst)
{
    assert(sock);

    if (!dst) {
        sock->flags &= ~SOCK_UDP_REMOTE;
        return 0;
    }

    if (sock->family != dst->family) {
        return -EINVAL;
    }

  /*  if (ipv6_addr_is_unspecified(dst->ipv6.addr)) {
        return -EINVAL;
    }*/

#if defined(SOCK_HAS_IPV4)
    if (dst->family == AF_INET) {
        if  (dst->addr.ipv4_u32 == 0xFFFFFFFF) {
            int enable = 1;
            if (setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) == -1) {
                perror("enabling broadcast");
            }
        }

        /* if an interface is specified, force it's usage. */
        _bind_to_device(sock->fd, dst->netif);
    }
#endif

    memset((void*)&sock->peer, '\0', sizeof(sockaddr_t));
    _endpoint_to_sockaddr(&sock->peer, dst);

    sock->flags |= SOCK_UDP_REMOTE;

    return 0;
}

ssize_t sock_udp_send(sock_udp_t *sock, const void* data, size_t len, const sock_udp_ep_t *remote)
{
    assert(sock);

    if (!remote && !(sock->flags & SOCK_UDP_REMOTE)) {
        /* no remote set, no remote supplied as parameter -> cannot send */
        return -EINVAL;
    }
    else if (remote && (sock->flags & SOCK_UDP_REMOTE)) {
        /* both remote set and remote supplied -> cannot send */
        return -EINVAL;
    }

    struct sockaddr *_remote;

    sockaddr_t sockaddr_tmp;
    if (remote) {
        /* create sockaddr struct from sock ep struct */
        _endpoint_to_sockaddr(&sockaddr_tmp, remote);
        _remote = (struct sockaddr *) &sockaddr_tmp;
    }
    else {
        /* use peer from sock struct */
        _remote = (struct sockaddr *)&sock->peer;
    }

    int res = sendto(sock->fd, data, len, 0, _remote, _addrlen(sock->family));
    if (res==-1) {
        perror("sendto");
    }

    return res;
}

ssize_t sock_udp_recv(sock_udp_t *sock, void* buf, size_t len, unsigned timeout, sock_udp_ep_t *remote)
{
    /* can only receive from sockets bound to address (or in(6)addr_any) */
    if (!(sock->flags & SOCK_UDP_LOCAL)) {
        return -EINVAL;
    }

    fd_set _select_fds;
    if (timeout != SOCK_NO_TIMEOUT) {
        int activity;
        struct timeval _timeout = { .tv_usec=timeout };

        FD_ZERO(&_select_fds);
        FD_SET(sock->fd, &_select_fds);
        activity = select(sock->fd + 1, &_select_fds, NULL, NULL, &_timeout);

        if (activity <= 0) {
            return -ETIMEDOUT;
        }
    }

    sockaddr_t sockaddr_remote = {0};
    unsigned socklen = sizeof(sockaddr_remote);
    ssize_t res = recvfrom(sock->fd, buf, len, 0, (struct sockaddr *)&sockaddr_remote, &socklen);
    if (remote && (res != -1)) {
        _sockaddr_to_endpoint(remote, &sockaddr_remote);
    }
    return res;
}
