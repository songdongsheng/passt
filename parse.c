// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * parse.c - Composable parsing helpers
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <assert.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "common.h"

/**
 * DOC: Theory of Operation
 *
 * These are a number of primitives which can be combined into parsers for
 * moderately complex input.  For simpler composability, they have common
 * conventions.
 *
 * - Functions return a bool indicating whether they successfully parsed.
 * - Any specific output from the parse is as output parameters
 * - First argument is always @cursor, a const char **.
 * - On entry, *@cursor has the point to start parsing.
 * - On successful exit, *@cursor is updated to the next character after the
 *    parsed portion of the input
 * - On failure, *@cursor and any output arguments are not modified
 *
 * For brevity the common parameters and return information are omitted from the
 * individual function documentation comments.
 */

/**
 * parse_literal() - Parse a specified literal string
 * @cursor:	Point to parse from, updated on success
 * @lit:	Keyword to accept
 */
bool parse_literal(const char **cursor, const char *lit)
{
	size_t len = strlen(lit);

	if (strlen(*cursor) < len || memcmp(*cursor, lit, len))
		return false;

	*cursor += len;
	return true;
}

/**
 * parse_eoi() - Parse end of input
 * @cursor:	Point to parse from
 *
 * Return: true if @p is at End of Input (\0), false otherwise
 */
bool parse_eoi(const char *cursor)
{
	return !(*cursor);
}
