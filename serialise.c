// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * serialise.c - Serialisation of data structures over bytestreams
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "serialise.h"

/**
 * read_all_buf() - Fill a whole buffer from a file descriptor
 * @fd:		File descriptor
 * @buf:	Pointer to base of buffer
 * @len:	Length of buffer
 *
 * Return: 0 on success, -1 on error (with errno set)
 *
 * #syscalls read
 */
int read_all_buf(int fd, void *buf, size_t len)
{
	size_t left = len;
	char *p = buf;

	while (left) {
		ssize_t rc;

		assert(left <= len);

		do
			rc = read(fd, p, left);
		while ((rc < 0) && errno == EINTR);

		if (rc < 0)
			return -1;

		if (rc == 0) {
			errno = ENODATA;
			return -1;
		}

		p += rc;
		left -= rc;
	}
	return 0;
}

/**
 * write_all_buf() - write all of a buffer to an fd
 * @fd:		File descriptor
 * @buf:	Pointer to base of buffer
 * @len:	Length of buffer
 *
 * Return: 0 on success, -1 on error (with errno set)
 *
 * #syscalls write
 */
int write_all_buf(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t left = len;

	while (left) {
		ssize_t rc;

		do
			rc = write(fd, p, left);
		while ((rc < 0) && errno == EINTR);

		if (rc < 0)
			return -1;

		p += rc;
		left -= rc;
	}
	return 0;
}
