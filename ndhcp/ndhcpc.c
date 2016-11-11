#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "ndhcpc.h"
#include "net/sock/udp.h"

#define DHCP_OFFER_MINLEN (48+192+4)
#define DHCP_MAGIC_COOKIE (0x63825363)

static void _handle_ack(uint8_t *buf, size_t res);

int ndhcpc_init(ndhcpc_t *n, unsigned iface, uint32_t xid)
{
    n->state = DHCP_STATE_DISCOVER;
    n->iface = iface;
    n->xid = htonl(xid);

    sock_udp_ep_t src = { .family = AF_INET, .addr.ipv4_u32=INADDR_ANY, .port=68 };
    sock_udp_ep_t dst = { .family = AF_INET, .addr.ipv4_u32=INADDR_BROADCAST, .port=67, .netif=iface };

    if (sock_udp_create(&n->sock, &src, &dst, 0) < 0) {
        fprintf(stderr, "ndhcpc: error creating socket.\n");
        exit(0);
    }

    return 0;
}

static void _create_pkt(ndhcpc_t *n, uint8_t *buf, unsigned secs, int broadcast)
{
    printf("ndhcpc: Sending discover...\n");

    dhcp_pkt_t *pkt = (dhcp_pkt_t *)buf;
    pkt->op_htype_hlen_hops = htonl(0x01010600);
    pkt->xid = n->xid;
    pkt->secs = htons(secs);
    if (broadcast) {
        pkt->flags = htons(0x8000);
    }
    pkt->magic_cookie = htonl(DHCP_MAGIC_COOKIE);


    if (ndhcpc_get_l2addr(n->iface, (uint8_t*)pkt->chaddr)) {
        puts("Cannot get interface mac address");
        exit(1);
    }
}

static void _send_discover(ndhcpc_t *n, uint8_t *buf, size_t len, unsigned secs)
{
    memset(buf, '\0', len);
    _create_pkt(n, buf, secs, 1);
    dhcp_pkt_t *pkt = (dhcp_pkt_t *)buf;
    const uint8_t _discover[] = {0x35, 0x01, 0x01, 0xff };
    memcpy(pkt->hdr_end, _discover, 4);
    ssize_t res = sock_udp_send(&n->sock, buf, sizeof(dhcp_pkt_t)+4, NULL);
    printf("_send_discover(): res=%zi\n", res);
}

static uint8_t *_opt_put(uint8_t *ptr, uint8_t type, void *data, size_t len)
{
    *ptr++ = type;
    *ptr++ = len;
    memcpy(ptr, data, len);
    return ptr + len;
}

static void _send_request(ndhcpc_t *n, uint8_t *buf, size_t len)
{
    (void)len;

    _create_pkt(n, buf, 0, 1);
    dhcp_pkt_t *pkt = (dhcp_pkt_t *)buf;

    uint8_t *opt_pos = pkt->hdr_end;

    /* DHCP request */
    uint8_t _tmp = 0x03;
    opt_pos = _opt_put(opt_pos, 53, &_tmp, 1);

    /* requested IP address */
    opt_pos = _opt_put(opt_pos, 50, &pkt->yiaddr, 4);

    /* DHCP server */
    opt_pos = _opt_put(opt_pos, 54, &pkt->siaddr, 4);

    /* end of options */
    *opt_pos++ = 0xff;

    ssize_t res = sock_udp_send(&n->sock, buf, opt_pos-buf, NULL);
    printf("_send_request(): res=%zi\n", res);
}

static void _receive(ndhcpc_t *n, uint8_t *buf, size_t len)
{
    sock_udp_ep_t remote;
    ssize_t res = sock_udp_recv(&n->sock, buf, len, 1000000, &remote);
    if (res < DHCP_OFFER_MINLEN) {
        puts("e minlen");
        printf("%zi\n", res);
        return;
    }

    dhcp_pkt_t *pkt = (dhcp_pkt_t *)buf;
    if (pkt->op_htype_hlen_hops != ntohl(0x02010600)) {
        puts("e op_htype_hlen_hops");
        return;
    }
    if ((pkt->xid != n->xid)) {
        puts("e xid");
        return;
    }
    if (pkt->hdr_end[0] != 53) {
        puts("e malf pkt");
        return;
    }

    switch (n->state) {
        case DHCP_STATE_DISCOVER:
            {
                if (pkt->hdr_end[2] != 0x02) {
                    puts("e no offer");
                    return;
                }
                puts("offer");
                n->state = DHCP_STATE_REQUEST;
                _send_request(n, buf, len);
                break;
            }
        case DHCP_STATE_REQUEST:
            {
                if (pkt->hdr_end[2] == 0x06) {
                    puts("NAK");
                    n->state = DHCP_STATE_DISCOVER;
                    return;
                }
                if (pkt->hdr_end[2] == 0x05) {
                    puts("ACK");
                    n->state = DHCP_STATE_BOUND;
                    _handle_ack(buf, res);
                }
                break;
            }
    }
}

static void _handle_ack(uint8_t *buf, size_t res)
{
    dhcp_lease_t lease = {0};
    dhcp_pkt_t *pkt = (dhcp_pkt_t *)buf;

    memcpy(&lease.addr, &pkt->yiaddr, 4);

    uint8_t *opt_pos = pkt->hdr_end;
    while (opt_pos < (uint8_t*)(buf + res) && (*opt_pos != 0xff)) {
        dhcp_opt_t *opt = (dhcp_opt_t *) opt_pos;
        switch (opt->type) {
            case 1:
                memcpy(&lease.netmask, opt->data, 4);
                break;
            case 3:
                memcpy(&lease.gw, opt->data, 4);
                break;
            case 6:
                memcpy(&lease.dns, opt->data, 4);
                break;
        }
        opt_pos += opt->len + 2;
    }

    ndhcpc_handle_lease(&lease);
}

int ndhcpc_loop(ndhcpc_t *n)
{
    uint8_t buf[512];
    int t = 0;
    while(1) {
        switch (n->state) {
            case DHCP_STATE_DISCOVER:
                _send_discover(n, buf, sizeof(buf), t++);
                /* fall through */
            case DHCP_STATE_REQUEST:
                _receive(n, buf, sizeof(buf));
                break;
            case DHCP_STATE_BOUND:
                {
                    exit(1);
                    break;
                }
            default:
                printf("unhandled case %u\n", n->state);
        };
    }

    return 0;
}
