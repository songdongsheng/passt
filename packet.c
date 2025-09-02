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
	if (len > PACKET_MAX_LEN) {
		debug("packet range length %zu (max %zu), %s:%i",
		      len, PACKET_MAX_LEN, func, line);
		return -1;
	}

	if (p->buf_size == 0) {
		int ret;

		ret = vu_packet_check_range((void *)p->buf, ptr, len);

		if (ret == -1)
			debug("cannot find region, %s:%i", func, line);

		return ret;
	}

	if (ptr < p->buf) {
		debug("packet range start %p before buffer start %p, %s:%i",
		      (void *)ptr, (void *)p->buf, func, line);
		return -1;
	}

	if (len > p->buf_size) {
		debug("packet range length %zu larger than buffer %zu, %s:%i",
		      len, p->buf_size, func, line);
		return -1;
	}

	if ((size_t)(ptr - p->buf) > p->buf_size - len) {
		debug("packet range %p, len %zu after buffer end %p, %s:%i",
		      (void *)ptr, len, (void *)(p->buf + p->buf_size),
		      func, line);
		return -1;
	}

	return 0;
}
/**
 * pool_full() - Is a packet pool full?
 * @p:		Pointer to packet pool
 *
 * Return: true if the pool is full, false if more packets can be added
 */
bool pool_full(const struct pool *p)
{
	return p->count >= p->size;
}

/**
 * packet_add_do() - Add data as packet descriptor to given pool
 * @p:		Existing pool
 * @data:	Data to add
 * @func:	For tracing: name of calling function
 * @line:	For tracing: caller line of function call
 */
void packet_add_do(struct pool *p, struct iov_tail *data,
		   const char *func, int line)
{
	size_t idx = p->count;
	const char *start;
	size_t len;

	if (pool_full(p)) {
		debug("add packet index %zu to pool with size %zu, %s:%i",
		      idx, p->size, func, line);
		return;
	}

	if (!iov_tail_prune(data))
		return;

	ASSERT(data->cnt == 1); /* we don't support iovec */

	len = data->iov[0].iov_len - data->off;
	start = (char *)data->iov[0].iov_base + data->off;

	if (packet_check_range(p, start, len, func, line))
		return;

	p->pkt[idx].iov_base = (void *)start;
	p->pkt[idx].iov_len = len;

	p->count++;
}

/**
 * packet_data_do() - Get data range from packet descriptor from given pool
 * @p:		Packet pool
 * @idx:	Index of packet descriptor in pool
 * @data:	IOV tail to store the address of the data (output)
 * @func:	For tracing: name of calling function, NULL means no trace()
 * @line:	For tracing: caller line of function call
 *
 * Return: false if packet index is invalid, true otherwise.
 * 	   If something wrong with @data, don't return at all (assert).
 */
bool packet_data_do(const struct pool *p, size_t idx,
		    struct iov_tail *data,
		    const char *func, int line)
{
	size_t i;

	ASSERT_WITH_MSG(p->count <= p->size,
			"Corrupted pool count: %zu, size: %zu, %s:%i",
			p->count, p->size, func, line);

	if (idx >= p->count) {
		debug("packet %zu from pool size: %zu, count: %zu, "
		      "%s:%i", idx, p->size, p->count, func, line);
		return false;
	}

	data->cnt = 1;
	data->off = 0;
	data->iov = &p->pkt[idx];

	for (i = 0; i < data->cnt; i++) {
		ASSERT_WITH_MSG(!packet_check_range(p, data->iov[i].iov_base,
						    data->iov[i].iov_len,
						    func, line),
				"Corrupt packet pool, %s:%i", func, line);
	}

	return true;
}

/**
 * pool_flush() - Flush a packet pool
 * @p:		Pointer to packet pool
 */
void pool_flush(struct pool *p)
{
	p->count = 0;
}
