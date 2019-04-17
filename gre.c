/*
 * gre.c - userspace GRE tunnel
 *
 * Copyright (C) 2015 - 2017, Xiaoxiao <i@pxx.io>
 * Copyright (C) 2019, Mikael Magnusson <mikma@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int tun;
static int sock;
static struct sockaddr_storage remote;
static size_t remote_len;

uint8_t buf[4096];

static void gre_cb(void);
static void gre_ipv4(const uint8_t *buf, int n);
static void gre_ipv6(const uint8_t *buf, int n, const struct sockaddr_in6 *src);
static void gre_any(const uint8_t *buf, int n);
static int tun_cb(void);
static int tun_new(const char *dev);
static int setnonblock(int fd);
static int runas(const char *user);
static int daemonize(void);
static int inet_addr_storage(const char *cp, struct sockaddr_storage *sp, size_t *sp_len);

int main(int argc, char **argv)
{
    fd_set readset;

    if (argc != 4)
    {
        printf("usage: %s <tun> remote local\n", argv[0]);
        return EXIT_FAILURE;
    }

    tun = tun_new(argv[1]);
    if (tun < 0)
    {
        printf("failed to init tun device\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_storage local;
    size_t local_len = 0;
    if (inet_addr_storage(argv[3], &local, &local_len))
    {
        fprintf(stderr, "bad local address\n");
        return EXIT_FAILURE;
    }

    sock = socket(local.ss_family, SOCK_RAW, IPPROTO_GRE);
    if (sock < 0)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (bind(sock, (struct sockaddr *)&local, local_len) != 0)
    {
        perror("bind");
        return EXIT_FAILURE;
    }

    if (inet_addr_storage(argv[2], &remote, &remote_len))
    {
        fprintf(stderr, "bad remote address\n");
        return EXIT_FAILURE;
    }

    setnonblock(sock);
    setnonblock(tun);
    runas("nobody");
    daemonize();

    int maxfd = (tun > sock ? tun : sock) + 1;
    while (1)
    {
        FD_ZERO(&readset);
        FD_SET(tun, &readset);
        FD_SET(sock, &readset);

        int r = select(maxfd, &readset, NULL, NULL, NULL);
        if (r < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                perror("select");
                break;
            }
        }

        if (FD_ISSET(sock, &readset))
        {
            gre_cb();
        }

        if (FD_ISSET(tun, &readset))
        {
            if (tun_cb() < 0)
                return 0;
        }
    }

    return 0;
}

static void gre_cb(void)
{
    int n;
    struct sockaddr_storage src;
    size_t src_len = sizeof(src);

    memset(&src, 0, src_len);
    n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &src_len);
    if (n < 0)
    {
        perror("recv");
        return;
    }

    switch (remote.ss_family) {
        case AF_INET: gre_ipv4(buf, n); break;
        case AF_INET6: gre_ipv6(buf, n, (const struct sockaddr_in6*)&src); break;
    }
}

static void gre_ipv4(const uint8_t *buf, int n)
{
    int ihl;    // IP header length

    ihl = 4 * (buf[0] & 0x0f);
    if (ihl > 60 || ihl < 20)
    {
        printf("IPv4 header too long\n");
        return;
    }
    // check source IPv4 address
    const struct sockaddr_in *remote_in = (const struct sockaddr_in *)&remote;
    if (*(uint32_t *)(buf + 12) != remote_in->sin_addr.s_addr)
    {
        return;
    }

    gre_any(buf + ihl, n - ihl);
}

static void gre_ipv6(const uint8_t *buf, int n, const struct sockaddr_in6 *src)
{
    if (n < 40)
    {
        return;
    }
    // check source IPv6 address
    const struct sockaddr_in6 *remote_in6 = (const struct sockaddr_in6 *)&remote;
    if (memcmp(src->sin6_addr.s6_addr, remote_in6->sin6_addr.s6_addr, 16) != 0)
    {
        return;
    }

    gre_any(buf, n);
}

static void gre_any(const uint8_t *buf, int n)
{
    // parse GRE header
    if (*(uint16_t *)(buf) != 0)
    {
        return;
    }
    uint16_t protocol = ntohs(*(uint16_t *)(buf + 2));
    if (protocol != ETHERTYPE_IP && protocol != ETHERTYPE_IPV6)
    {
        return;
    }

    write(tun, buf, n);
}

static int tun_cb(void)
{
    int n;

    n = read(tun, buf, sizeof(buf));
    if (n < 0)
    {
        int err = errno;
        perror("read");
        if (err == EBADFD)
            return -1;

        return 0;
    }
    buf[0] = 0;
    buf[1] = 0;
    uint16_t proto = ntohs(*(uint16_t *)(buf + 2));
    if (proto != ETHERTYPE_IP && proto != ETHERTYPE_IPV6)
    {
        return 0;
    }
    sendto(sock, buf, n, 0, (struct sockaddr *)&remote, remote_len);
    return 0;
}

static int tun_new(const char *dev)
{
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        return -1;
    }

    bzero(&ifr, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TUN;
    if (*dev != '\0')
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
    {
        return err;
    }
    return fd;
}

static int setnonblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        return -1;
    }
    if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK))
    {
        return -1;
    }
    return 0;
}

static int runas(const char *user)
{
    struct passwd *pw_ent = getpwnam(user);

    if (pw_ent != NULL)
    {
        if (setegid(pw_ent->pw_gid) != 0)
        {
            return -1;
        }
        if (seteuid(pw_ent->pw_uid) != 0)
        {
            return -1;
        }
    }

    return 0;
}

static int daemonize(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return -1;
    }

    if (pid > 0)
    {
        exit(0);
    }

    umask(0);

    if (setsid() < 0)
    {
        perror("setsid");
        return -1;
    }

    return 0;
}

static int inet_addr_storage(const char *cp, struct sockaddr_storage *sp, size_t *sp_len)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST | AI_ADDRCONFIG;
    res = getaddrinfo(cp, NULL, &hints, &result);
    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        return -1;
    }

    memcpy(sp, result->ai_addr, result->ai_addrlen);
    *sp_len = result->ai_addrlen;

    freeaddrinfo(result);
    result = NULL;

    if (sp->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sp;
        sin->sin_port = htons(IPPROTO_GRE);
    } else if (sp->ss_family == AF_INET6) {
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sp;
        sin->sin6_port = htons(IPPROTO_GRE);
    }

    return 0;
}
