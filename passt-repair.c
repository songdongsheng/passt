// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * passt-repair.c - Privileged helper to set/clear TCP_REPAIR on sockets
 *
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * Connect to passt via UNIX domain socket, receive sockets via SCM_RIGHTS along
 * with byte commands mapping to TCP_REPAIR values, and switch repair mode on or
 * off. Reply by echoing the command. Exit on EOF.
 */

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <netdb.h>

#include <netinet/tcp.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "seccomp_repair.h"

#define SCM_MAX_FD 253 /* From Linux kernel (include/net/scm.h), not in UAPI */

/**
 * main() - Entry point and whole program with loop
 * @argc:	Argument count, must be 2
 * @argv:	Argument: path of UNIX domain socket to connect to
 *
 * Return: 0 on success (EOF), 1 on error, 2 on usage error
 *
 * #syscalls:repair connect setsockopt write close exit_group
 * #syscalls:repair socket s390x:socketcall i686:socketcall
 * #syscalls:repair recvfrom recvmsg arm:recv ppc64le:recv
 * #syscalls:repair sendto sendmsg arm:send ppc64le:send
 */
int main(int argc, char **argv)
{
	char buf[CMSG_SPACE(sizeof(int) * SCM_MAX_FD)]
	     __attribute__ ((aligned(__alignof__(struct cmsghdr))));
	struct sockaddr_un a = { AF_UNIX, "" };
	int fds[SCM_MAX_FD], s, ret, i, n = 0;
	struct sock_fprog prog;
	int8_t cmd = INT8_MAX;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;

	prctl(PR_SET_DUMPABLE, 0);

	prog.len = (unsigned short)sizeof(filter_repair) /
				   sizeof(filter_repair[0]);
	prog.filter = filter_repair;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		fprintf(stderr, "Failed to apply seccomp filter");
		_exit(1);
	}

	iov = (struct iovec){ &cmd, sizeof(cmd) };
	msg = (struct msghdr){ .msg_name = NULL, .msg_namelen = 0,
			       .msg_iov = &iov, .msg_iovlen = 1,
			       .msg_control = buf,
			       .msg_controllen = sizeof(buf),
			       .msg_flags = 0 };
	cmsg = CMSG_FIRSTHDR(&msg);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s PATH\n", argv[0]);
		_exit(2);
	}

	ret = snprintf(a.sun_path, sizeof(a.sun_path), "%s", argv[1]);
	if (ret <= 0 || ret >= (int)sizeof(a.sun_path)) {
		fprintf(stderr, "Invalid socket path: %s\n", argv[1]);
		_exit(2);
	}

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Failed to create AF_UNIX socket: %i\n", errno);
		_exit(1);
	}

	if (connect(s, (struct sockaddr *)&a, sizeof(a))) {
		fprintf(stderr, "Failed to connect to %s: %s\n", argv[1],
			strerror(errno));
		_exit(1);
	}

loop:
	ret = recvmsg(s, &msg, 0);
	if (ret < 0) {
		if (errno == ECONNRESET) {
			ret = 0;
		} else {
			fprintf(stderr, "Failed to read message: %i\n", errno);
			_exit(1);
		}
	}

	if (!ret)	/* Done */
		_exit(0);

	if (!cmsg ||
	    cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
	    cmsg->cmsg_len > CMSG_LEN(sizeof(int) * SCM_MAX_FD) ||
	    cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "No/bad ancillary data from peer\n");
		_exit(1);
	}

	/* No inverse formula for CMSG_LEN(x), and building one with CMSG_LEN(0)
	 * works but there's no guarantee it does. Search the whole domain.
	 */
	for (i = 1; i < SCM_MAX_FD; i++) {
		if (CMSG_LEN(sizeof(int) * i) == cmsg->cmsg_len) {
			n = i;
			break;
		}
	}
	if (!n) {
		fprintf(stderr, "Invalid ancillary data length %zu from peer\n",
			cmsg->cmsg_len);
		_exit(1);
	}

	memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * n);

	if (cmd != TCP_REPAIR_ON && cmd != TCP_REPAIR_OFF &&
	    cmd != TCP_REPAIR_OFF_NO_WP) {
		fprintf(stderr, "Unsupported command 0x%04x\n", cmd);
		_exit(1);
	}

	for (i = 0; i < n; i++) {
		int o = cmd;

		if (setsockopt(fds[i], SOL_TCP, TCP_REPAIR, &o, sizeof(o))) {
			fprintf(stderr,
				"Setting TCP_REPAIR to %i on socket %i: %s", o,
				fds[i], strerror(errno));
			_exit(1);
		}

		/* Close _our_ copy */
		close(fds[i]);

		/* Confirm setting by echoing the command back */
		if (send(s, &cmd, sizeof(cmd), 0) < 0) {
			fprintf(stderr, "Reply to command %i: %s\n",
				o, strerror(errno));
			_exit(1);
		}
	}

	goto loop;

	return 0;
}
