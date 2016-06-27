/*
 * gre.c - userspace GRE tunnel
 *
 * Copyright (C) 2015, Xiaoxiao <i@xiaoxiao.im>
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
#include <net/if.h>
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
static struct sockaddr_in remote;

uint8_t buf[4096];

static void gre_cb(void);
static void tun_cb(void);
static int tun_new(const char *dev);
static int setnonblock(int fd);
static int runas(const char *user);
static int daemonize(void);

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

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
	if (sock < 0)
	{
		perror("socket");
		return EXIT_FAILURE;
	}

	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(IPPROTO_GRE);
	local.sin_addr.s_addr = inet_addr(argv[3]);
	if (local.sin_addr.s_addr == INADDR_NONE)
	{
		fprintf(stderr, "bad local address\n");
		return EXIT_FAILURE;
	}
	else
	{
		if (bind(sock, (struct sockaddr *)&local, sizeof(local)) != 0)
		{
			perror("bind");
			return EXIT_FAILURE;
		}
	}

	remote.sin_family = AF_INET;
	remote.sin_port = htons(IPPROTO_GRE);
	remote.sin_addr.s_addr = inet_addr(argv[2]);
	if (remote.sin_addr.s_addr == INADDR_NONE)
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
			tun_cb();
		}
	}

	return 0;
}

static void gre_cb(void)
{
	int ihl;	// IP header length
	int n;

	n = recv(sock, buf, sizeof(buf), 0);
	if (n < 0)
	{
		perror("recv");
		return;
	}
	ihl = 4 * (buf[0] & 0x0f);
	if (ihl > 60 || ihl < 20)
	{
		printf("IPv4 header too long\n");
		return;
	}
	// check source IPv4 address
	if (*(uint32_t *)(buf + 12) != remote.sin_addr.s_addr)
	{
		return;
	}

	// parse GRE header
	if (*(uint16_t *)(buf + ihl) != 0)
	{
		return;
	}
	uint16_t protocol = ntohs(*(uint16_t *)(buf + ihl + 2));
	if (protocol != 0x0800)
	{
		return;
	}

	write(tun, buf + ihl + 4, n - ihl - 4);
}

static void tun_cb(void)
{
	int n;

	n = read(tun, buf + 4, sizeof(buf) - 4);
	if (n < 0)
	{
		perror("read");
		return;
	}
	*(uint16_t *)(buf) = 0;
	*(uint16_t *)(buf + 2) = htons(0x0800);
	sendto(sock, buf, n + 4, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr));
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

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
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
