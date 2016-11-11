#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <unistd.h>

#include "ndhcpc.h"

#ifndef NDHCP_SCRIPT
#define NDHCP_SCRIPT "/tmp/ndhcpc.script"
#endif

int ndhcpc_get_l2addr(unsigned iface, uint8_t *dst)
{
    struct ifreq ifr;

    int fd=socket(AF_UNIX,SOCK_DGRAM,0);
    if (fd==-1) {
        printf("%s",strerror(errno));
        return 1;
    }

    ifr.ifr_ifindex = iface;
    if (ioctl(fd,SIOCGIFNAME,&ifr)==-1) {
        int temp_errno=errno;
        close(fd);
        printf("%s",strerror(temp_errno));
        return 1;
    }

    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
        int temp_errno=errno;
        close(fd);
        printf("%s",strerror(temp_errno));
        return 1;
    }
    close(fd);

    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
        puts("not an Ethernet interface");
        return 1;
    }

    memcpy(dst, (unsigned char*)ifr.ifr_hwaddr.sa_data, 6);

    return 0;
}

static void _setenv_ipaddr(const char *name, uint32_t addr)
{
    char buf[16];
    uint8_t *_addr = (uint8_t *)&addr;
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            (unsigned)_addr[0], (unsigned)_addr[1], (unsigned)_addr[2], (unsigned)_addr[3]);
    setenv(name, buf, 1);
}

static void _setenv_int(const char *name, int val)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%i", val);
    setenv(name, buf, 1);
}


void ndhcpc_handle_lease(dhcp_lease_t *lease)
{
    _setenv_ipaddr("IPV4_ADDRESS", lease->addr);
    _setenv_ipaddr("IPV4_NETMASK", lease->netmask);
    _setenv_ipaddr("IPV4_GATEWAY", lease->gw);
    _setenv_ipaddr("IPV4_DNS", lease->dns);
    _setenv_int("IPV4_MTU", lease->mtu);
    system(NDHCP_SCRIPT);
}
