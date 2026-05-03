/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Definitions and functions used by both client and server of the configuration
 * update protocol (pesto).
 */

#ifndef PESTO_H
#define PESTO_H

#include <assert.h>
#include <stdint.h>

#define PESTO_SERVER_MAGIC	"basil:s"

/* Version 0 is reserved for unreleased / unsupported experimental versions */
#define PESTO_PROTOCOL_VERSION	1

/**
 * struct pesto_hello - Server introduction message
 * @magic:	PESTO_SERVER_MAGIC
 * @version:	Version number
 */
struct pesto_hello {
	char magic[8];
	uint32_t version;
} __attribute__ ((__packed__));

static_assert(sizeof(PESTO_SERVER_MAGIC)
	      == sizeof(((struct pesto_hello *)0)->magic),
	      "PESTO_SERVER_MAGIC has wrong size");

#endif /* PESTO_H */
