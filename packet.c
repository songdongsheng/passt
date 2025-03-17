// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * packet.c - Packet abstraction: add packets to pool, flush, get packet data
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/ip6.h>

#include "packet.h"
#include "util.h"
#include "log.h"

/**
 * packet_check_range() - Check if a memory range is valid for a pool
 * @p:		Packet pool
 * @ptr:	Start of desired data range
 * @len:	Length of desired data range
 * @func:	For tracing: name of calling function
 * @line:	For tracing: caller line of function call
 *
 * Return: 0 if the range is valid, -1 otherwise
 */
static int packet_check_range(const struct pool *p, const char *ptr, size_t len,
			      const char *func, int line)
{
	if (p->buf_size == 0) {
		int ret;

		ret = vu_packet_check_range((void *)p->buf, ptr, len);

		if (ret == -1)
			trace("cannot find region, %s:%i", func, line);

		return ret;
	}

	if (ptr < p->buf) {
		trace("packet range start %p before buffer start %p, %s:%i",
		      (void *)ptr, (void *)p->buf, func, line);
		return -1;
	}

	if (len > p->buf_size) {
		trace("packet range length %zu larger than buffer %zu, %s:%i",
		      len, p->buf_size, func, line);
		return -1;
	}

	if ((size_t)(ptr - p->buf) > p->buf_size - len) {
		trace("packet range %p, len %zu after buffer end %p, %s:%i",
		      (void *)ptr, len, (void *)(p->buf + p->buf_size),
		      func, line);
		return -1;
	}

	return 0;
}
/**
 * packet_add_do() - Add data as packet descriptor to given pool
 * @p:		Existing pool
 * @len:	Length of new descriptor
 * @start:	Start of data
 * @func:	For tracing: name of calling function, NULL means no trace()
 * @line:	For tracing: caller line of function call
 */
void packet_add_do(struct pool *p, size_t len, const char *start,
		   const char *func, int line)
{
	size_t idx = p->count;

	if (idx >= p->size) {
		trace("add packet index %zu to pool with size %zu, %s:%i",
		      idx, p->size, func, line);
		return;
	}

	if (packet_check_range(p, start, len, func, line))
		return;

	if (len > PACKET_MAX_LEN) {
		trace("add packet length %zu, %s:%i", len, func, line);
		return;
	}

	p->pkt[idx].iov_base = (void *)start;
	p->pkt[idx].iov_len = len;

	p->count++;
}

/**
 * packet_get_do() - Get data range from packet descriptor from given pool
 * @p:		Packet pool
 * @idx:	Index of packet descriptor in pool
 * @offset:	Offset of data range in packet descriptor
 * @len:	Length of desired data range
 * @left:	Length of available data after range, set on return, can be NULL
 * @func:	For tracing: name of calling function, NULL means no trace()
 * @line:	For tracing: caller line of function call
 *
 * Return: pointer to start of data range, NULL on invalid range or descriptor
 */
void *packet_get_do(const struct pool *p, size_t idx, size_t offset,
		    size_t len, size_t *left, const char *func, int line)
{
	char *ptr;

	if (idx >= p->size || idx >= p->count) {
		if (func) {
			trace("packet %zu from pool size: %zu, count: %zu, "
			      "%s:%i", idx, p->size, p->count, func, line);
		}
		return NULL;
	}

	if (len > PACKET_MAX_LEN) {
		if (func) {
			trace("packet data length %zu, %s:%i",
			      len, func, line);
		}
		return NULL;
	}

	if (len + offset > p->pkt[idx].iov_len) {
		if (func) {
			trace("data length %zu, offset %zu from length %zu, "
			      "%s:%i", len, offset, p->pkt[idx].iov_len,
			      func, line);
		}
		return NULL;
	}

	ptr = (char *)p->pkt[idx].iov_base + offset;

	if (packet_check_range(p, ptr, len, func, line))
		return NULL;

	if (left)
		*left = p->pkt[idx].iov_len - offset - len;

	return ptr;
}

/**
 * pool_flush() - Flush a packet pool
 * @p:		Pointer to packet pool
 */
void pool_flush(struct pool *p)
{
	p->count = 0;
}
