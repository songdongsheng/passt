/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>

bool parse_literal(const char **cursor, const char *lit);
bool parse_eoi(const char *cursor);

#endif /* _PARSE_H */
