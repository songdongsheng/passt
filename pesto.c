// SPDX-License-Identifier: GPL-2.0-or-later

/* PESTO - Programmable Extensible Socket Translation Orchestrator
 *  front-end for passt(1) and pasta(1) forwarding configuration
 *
 * pesto.c - Main program (it's not actually extensible)
 *
 * Copyright (c) 2026 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "common.h"
#include "seccomp_pesto.h"
#include "pesto.h"
#include "log.h"

bool debug_flag = false;

static char stdout_buf[BUFSIZ];

/**
 * usage() - Print usage, exit with given status code
 * @name:	Executable name
 * @f:		Stream to print usage info to
 * @status:	Status code for exit(2)
 *
 * #syscalls:pesto exit_group fstat write
 */
static void usage(const char *name, FILE *f, int status)
{
	FPRINTF(f, "Usage: %s [OPTION]... PATH\n", name);
	FPRINTF(f,
		"\n"
		"  -d, --debug		Print debugging messages\n"
		"  -h, --help		Display this help message and exit\n"
		"  --version		Show version and exit\n");
	exit(status);
}

/**
 * main() - Dynamic reconfiguration client main program
 * @argc:	Argument count
 * @argv:	Arguments: socket path, operation, port specifiers
 *
 * Return: 0 on success, won't return on failure
 *
 * #syscalls:pesto exit_group fstat read write
 */
int main(int argc, char **argv)
{
	const struct option options[] = {
		{"debug",	no_argument,		NULL,		'd' },
		{"help",	no_argument,		NULL,		'h' },
		{"version",	no_argument,		NULL,		1 },
		{ 0 },
	};
	const char *optstring = "dh";
	struct sock_fprog prog;
	int optname;

	prctl(PR_SET_DUMPABLE, 0);

	prog.len = (unsigned short)sizeof(filter_pesto) /
				   sizeof(filter_pesto[0]);
	prog.filter = filter_pesto;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		die("Failed to apply seccomp filter");

	/* Explicitly set stdout buffer, otherwise printf() might allocate,
	 * breaking our seccomp profile.
	 */
	if (setvbuf(stdout, stdout_buf, _IOFBF, sizeof(stdout_buf)))
		die_perror("Failed to set stdout buffer");

	do {
		optname = getopt_long(argc, argv, optstring, options, NULL);

		switch (optname) {
		case -1:
		case 0:
			break;
		case 'h':
			usage(argv[0], stdout, EXIT_SUCCESS);
			break;
		case 'd':
			debug_flag = true;
			break;
		case 1:
			FPRINTF(stdout, "pesto ");
			FPRINTF(stdout, VERSION_BLOB);
			exit(EXIT_SUCCESS);
		default:
			usage(argv[0], stderr, EXIT_FAILURE);
		}
	} while (optname != -1);

	if (argc - optind != 1)
		usage(argv[0], stderr, EXIT_FAILURE);

	debug("debug_flag=%d, path=\"%s\"", debug_flag, argv[optind]);

	die("pesto is not implemented yet");
}
