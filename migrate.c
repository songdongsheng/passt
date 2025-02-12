// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * migrate.c - Migration sections, layout, and routines
 *
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <errno.h>
#include <sys/uio.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "inany.h"
#include "flow.h"
#include "flow_table.h"

#include "migrate.h"

/* Magic identifier for migration data */
#define MIGRATE_MAGIC		0xB1BB1D1B0BB1D1B0

/* Stages for version 1 */
static const struct migrate_stage stages_v1[] = {
	{ 0 },
};

/* Supported encoding versions, from latest (most preferred) to oldest */
static const struct migrate_version versions[] = {
	{ 1,	stages_v1, },
	{ 0 },
};

/* Current encoding version */
#define CURRENT_VERSION		(&versions[0])

/**
 * migrate_source() - Migration as source, send state to hypervisor
 * @c:		Execution context
 * @fd:		File descriptor for state transfer
 *
 * Return: 0 on success, positive error code on failure
 */
static int migrate_source(struct ctx *c, int fd)
{
	const struct migrate_version *v = CURRENT_VERSION;
	const struct migrate_header header = {
		.magic		= htonll_constant(MIGRATE_MAGIC),
		.version	= htonl(v->id),
		.compat_version	= htonl(v->id),
	};
	const struct migrate_stage *s;
	int ret;

	if (write_all_buf(fd, &header, sizeof(header))) {
		ret = errno;
		err("Can't send migration header: %s, abort", strerror_(ret));
		return ret;
	}

	for (s = v->s; s->name; s++) {
		if (!s->source)
			continue;

		debug("Source side migration stage: %s", s->name);

		if ((ret = s->source(c, s, fd))) {
			err("Source migration stage: %s: %s, abort", s->name,
			    strerror_(ret));
			return ret;
		}
	}

	return 0;
}

/**
 * migrate_target_read_header() - Read header in target
 * @fd:		Descriptor for state transfer
 *
 * Return: version structure on success, NULL on failure with errno set
 */
static const struct migrate_version *migrate_target_read_header(int fd)
{
	const struct migrate_version *v;
	struct migrate_header h;
	uint32_t id, compat_id;

	if (read_all_buf(fd, &h, sizeof(h)))
		return NULL;

	id = ntohl(h.version);
	compat_id = ntohl(h.compat_version);

	debug("Source magic: 0x%016" PRIx64 ", version: %u, compat: %u",
	      ntohll(h.magic), id, compat_id);

	if (ntohll(h.magic) != MIGRATE_MAGIC || !id || !compat_id) {
		err("Invalid incoming device state");
		errno = EINVAL;
		return NULL;
	}

	for (v = versions; v->id; v++)
		if (v->id <= id && v->id >= compat_id)
			return v;

	errno = ENOTSUP;
	err("Unsupported device state version: %u", id);
	return NULL;
}

/**
 * migrate_target() - Migration as target, receive state from hypervisor
 * @c:		Execution context
 * @fd:		File descriptor for state transfer
 *
 * Return: 0 on success, positive error code on failure
 */
static int migrate_target(struct ctx *c, int fd)
{
	const struct migrate_version *v;
	const struct migrate_stage *s;
	int ret;

	if (!(v = migrate_target_read_header(fd)))
		return errno;

	for (s = v->s; s->name; s++) {
		if (!s->target)
			continue;

		debug("Target side migration stage: %s", s->name);

		if ((ret = s->target(c, s, fd))) {
			err("Target migration stage: %s: %s, abort", s->name,
			    strerror_(ret));
			return ret;
		}
	}

	return 0;
}

/**
 * migrate_init() - Set up things necessary for migration
 * @c:		Execution context
 */
void migrate_init(struct ctx *c)
{
	c->device_state_result = -1;
}

/**
 * migrate_close() - Close migration channel
 * @c:		Execution context
 */
void migrate_close(struct ctx *c)
{
	if (c->device_state_fd != -1) {
		debug("Closing migration channel, fd: %d", c->device_state_fd);
		close(c->device_state_fd);
		c->device_state_fd = -1;
		c->device_state_result = -1;
	}
}

/**
 * migrate_request() - Request a migration of device state
 * @c:		Execution context
 * @fd:		fd to transfer state
 * @target:	Are we the target of the migration?
 */
void migrate_request(struct ctx *c, int fd, bool target)
{
	debug("Migration requested, fd: %d (was %d)", fd, c->device_state_fd);

	if (c->device_state_fd != -1)
		migrate_close(c);

	c->device_state_fd = fd;
	c->migrate_target = target;
}

/**
 * migrate_handler() - Send/receive passt internal state to/from hypervisor
 * @c:		Execution context
 */
void migrate_handler(struct ctx *c)
{
	int rc;

	if (c->device_state_fd < 0)
		return;

	debug("Handling migration request from fd: %d, target: %d",
	      c->device_state_fd, c->migrate_target);

	if (c->migrate_target)
		rc = migrate_target(c, c->device_state_fd);
	else
		rc = migrate_source(c, c->device_state_fd);

	migrate_close(c);

	c->device_state_result = rc;
}
