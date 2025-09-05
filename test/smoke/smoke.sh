#! /bin/sh
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# test/smoke/smoke.sh - Basic smoke tests
#
# Copyright Red Hat
# Author: David Gibson <david@gibson.dropbear.id.au>

. $(dirname $0)/../exeter/sh/exeter.sh

PASST=$(dirname $0)/../../passt
PASTA=$(dirname $0)/../../pasta

exeter_register passt_version $PASST --version
exeter_set_description passt_version "Check passt --version works"

exeter_register pasta_version $PASTA --version
exeter_set_description pasta_version "Check pasta --version works"

exeter_register passt_help $PASST --help
exeter_set_description passt_help "Check passt --help works"

exeter_register pasta_help $PASTA --help
exeter_set_description pasta_help "Check pasta --help works"

exeter_main "$@"
