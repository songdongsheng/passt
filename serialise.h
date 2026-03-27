/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef SERIALISE_H
#define SERIALISE_H

#include <stddef.h>

int read_all_buf(int fd, void *buf, size_t len);
int write_all_buf(int fd, const void *buf, size_t len);

#endif /* SERIALISE_H */
