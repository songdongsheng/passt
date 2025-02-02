# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# Copyright (c) 2025 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

TARGETS = source target
CFLAGS = -Wall -Wextra -pedantic

all: $(TARGETS)

$(TARGETS): %: %.c

clean:
	rm -f $(TARGETS)
