// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * doc/migration/target.c - Mock of TCP migration target, use with passt-repair
 *
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>

int main(int argc, char **argv)
{
	struct sockaddr_in a = { AF_INET, htons(atoi(argv[3])), { 0 }, { 0 } };
	struct addrinfo hints = { 0, AF_UNSPEC, SOCK_STREAM, 0, 0,
				  NULL, NULL, NULL };
	struct sockaddr_un a_helper = { AF_UNIX, { 0 } };
	int s, s_helper, seq;
	int8_t cmd;
	struct iovec iov = { &cmd, sizeof(cmd) };
	char buf[CMSG_SPACE(sizeof(int))];
	struct msghdr msg = { NULL, 0, &iov, 1, buf, sizeof(buf), 0 };
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	struct addrinfo *r;

	(void)argc;

	strcpy(a_helper.sun_path, argv[4]);
	getaddrinfo(argv[1], argv[2], &hints, &r);

	if (argc != 7) {
		fprintf(stderr,
			"%s DST_ADDR DST_PORT SRC_PORT HELPER_PATH SSEQ RSEQ\n",
			argv[0]);
		return -1;
	}

	/* Prepare socket, bind to source port */
	s = socket(r->ai_family, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &((int){ 1 }), sizeof(int));
	bind(s, (struct sockaddr *)&a, sizeof(a));

	/* Wait for helper */
	s_helper = socket(AF_UNIX, SOCK_STREAM, 0);
	unlink(a_helper.sun_path);
	bind(s_helper, (struct sockaddr *)&a_helper, sizeof(a_helper));
	listen(s_helper, 1);
	s_helper = accept(s_helper, NULL, NULL);

	/* Set up message for helper, with socket */
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &s, sizeof(s));

	/* Send command to helper: turn repair mode on, wait for reply */
	cmd = TCP_REPAIR_ON;
	sendmsg(s_helper, &msg, 0);
	recv(s_helper, &((int){ 0 }), 1, 0);

	/* Set sending sequence */
	seq = TCP_SEND_QUEUE;
	setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &seq, sizeof(seq));
	seq = atoi(argv[5]);
	setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq));

	/* Set receiving sequence */
	seq = TCP_RECV_QUEUE;
	setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &seq, sizeof(seq));
	seq = atoi(argv[6]);
	setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq));

	/* Connect setting kernel state only, without actual SYN / handshake */
	connect(s, r->ai_addr, r->ai_addrlen);

	/* Send command to helper: turn repair mode off, wait for reply */
	cmd = TCP_REPAIR_OFF;
	sendmsg(s_helper, &msg, 0);

	recv(s_helper, &((int8_t){ 0 }), 1, 0);

	/* Terminate helper */
	close(s_helper);

	/* Send some more data */
	send(s, "after migration\n", sizeof("after migration\n"), 0);
}
