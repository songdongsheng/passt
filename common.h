/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Definitions used by both passt/pasta and other tools
 */

#ifndef COMMON_H
#define COMMON_H

#include <string.h>

#define VERSION_BLOB							       \
	VERSION "\n"							       \
	"Copyright Red Hat\n"						       \
	"GNU General Public License, version 2 or later\n"		       \
	"  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>\n"	       \
	"This is free software: you are free to change and redistribute it.\n" \
	"There is NO WARRANTY, to the extent permitted by law.\n\n"

/* FPRINTF() intentionally silences cert-err33-c clang-tidy warnings */
#define FPRINTF(f, ...)	(void)fprintf(f, __VA_ARGS__)

#endif /* COMMON_H */
