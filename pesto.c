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
#include "serialise.h"
#include "fwd_rule.h"
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

/* Maximum number of pifs with rule tables */
#define MAX_PIFS	3

struct pif_configuration {
	uint8_t pif;
	char name[PIF_NAME_SIZE];
	struct fwd_table fwd;
};

struct configuration {
	uint32_t npifs;
	struct pif_configuration pif[MAX_PIFS];
};

/**
 * pif_conf_by_num() - Find a pif's configuration by pif id
 * @conf:	Configuration description
 * @pif:	pif id
 *
 * Return: pointer to the pif_configuration for @pif, or NULL if not found
 */
static struct pif_configuration *pif_conf_by_num(struct configuration *conf,
						 uint8_t pif)
{
	unsigned i;

	for (i = 0; i < conf->npifs; i++) {
		if (conf->pif[i].pif == pif)
			return &conf->pif[i];
	}

	return NULL;
}

/**
 * pif_conf_by_name() - Find a pif's configuration by name
 * @conf:	Configuration description
 * @name:	Interface name
 *
 * Return: pif_configuration for pif named @name, or NULL if not found
 */
static struct pif_configuration *pif_conf_by_name(struct configuration *conf,
						  const char *name)
{
	unsigned i;

	for (i = 0; i < conf->npifs; i++) {
		if (strcmp(conf->pif[i].name, name) == 0)
			return &conf->pif[i];
	}

	return NULL;
}

/**
 * pesto_read_rules() - Read rulestate from passt/pasta
 * @fd:		Control socket
 * @conf:	Configuration description to update
 */
static bool read_pif_conf(int fd, struct configuration *conf)
{
	struct pif_configuration *pc;
	struct pesto_pif_info info;
	uint8_t pif;
	unsigned i;

	if (read_u8(fd, &pif) < 0)
		die("Error reading from control socket");

	if (pif == PIF_NONE)
		return false;

	debug("Receiving config for PIF %"PRIu8, pif);

	if (conf->npifs >= ARRAY_SIZE(conf->pif)) {
		die("passt has more pifs than pesto can manage (max %d)",
		    ARRAY_SIZE(conf->pif));
	}

	pc = &conf->pif[conf->npifs];
	pc->pif = pif;

	if (read_all_buf(fd, &info, sizeof(info)) < 0)
		die("Error reading from control socket");

	if (info.name[sizeof(info.name)-1])
		die("Interface name was not NULL terminated");
	/* Redundant, to make static checkers happy */
	info.name[sizeof(info.name) - 1] = '\0';

	static_assert(sizeof(info.name) == sizeof(pc->name),
		      "Mismatching pif name lengths");
	memcpy(pc->name, info.name, sizeof(pc->name));
	pc->fwd.caps = ntohl(info.caps);

	pc->fwd.count = ntohl(info.count);
	if (pc->fwd.count > MAX_FWD_RULES)
		die("Too many forwarding rules");

	debug("PIF %"PRIu8": %s, %"PRIu32" rules, capabilities 0x%"PRIx32
	      ":%s%s%s%s%s%s", pc->pif, pc->name, pc->fwd.count, pc->fwd.caps,
	      pc->fwd.caps & FWD_CAP_IPV4 ? " IPv4" : "",
	      pc->fwd.caps & FWD_CAP_IPV6 ? " IPv6" : "",
	      pc->fwd.caps & FWD_CAP_TCP ? " TCP" : "",
	      pc->fwd.caps & FWD_CAP_UDP ? " UDP" : "",
	      pc->fwd.caps & FWD_CAP_SCAN ? " scan" : "",
	      pc->fwd.caps & FWD_CAP_IFNAME ? " ifname" : "");

	/* O(n^2), but n is bounded by MAX_PIFS */
	if (pif_conf_by_num(conf, pc->pif))
		die("Received duplicate interface identifier");

	/* O(n^2), but n is bounded by MAX_PIFS */
	if (pif_conf_by_name(conf, pc->name))
		die("Received duplicate interface name");

	/* NOTE: We read the fwd rules directly into fwd.rules, rather than
	 * using fwd_rule_add().  This means we can read and display rules even
	 * if something has gone wrong (in pesto or passt) and we get rules that
	 * fwd_rule_add() would reject.  It does have the side effect that we
	 * never assign socket space for the fwd rules, but we don't need that
	 * within pesto.
	 */
	for (i = 0; i < pc->fwd.count; i++) {
		if (fwd_rule_read(fd, &pc->fwd.rules[i]) < 0)
			die("Error reading from control socket");
	}

	conf->npifs++;
	return true;
}

/**
 * show_conf() - Show current configuration obtained from passt/pasta
 * @conf:	Configuration description
 */
static void show_conf(const struct configuration *conf)
{
	unsigned i;

	for (i = 0; i < conf->npifs; i++) {
		const struct pif_configuration *pc = &conf->pif[i];
		printf("  %s\n", pc->name);
		fwd_rules_dump(printf, pc->fwd.rules, pc->fwd.count,
			       "    ", "\n");
	}
}

/**
 * main() - Dynamic reconfiguration client main program
 * @argc:	Argument count
 * @argv:	Arguments: socket path, operation, port specifiers
 *
 * Return: 0 on success, won't return on failure
 *
 * #syscalls:pesto socket s390x:socketcall i686:socketcall
 * #syscalls:pesto connect shutdown close
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
	struct sockaddr_un a = { AF_UNIX, "" };
	struct configuration conf = { 0 };
	const char *optstring = "dh";
	struct pesto_hello hello;
	struct sock_fprog prog;
	int optname, ret, s;
	uint32_t s_version;

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

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		die_perror("Failed to create AF_UNIX socket");

	ret = snprintf(a.sun_path, sizeof(a.sun_path), "%s", argv[optind]);
	if (ret <= 0 || ret >= (int)sizeof(a.sun_path))
		die("Invalid socket path \"%s\"", argv[optind]);

	ret = connect(s, (struct sockaddr *)&a, sizeof(a));
	if (ret < 0) {
		die_perror("Failed to connect to %s", a.sun_path);
	}

	ret = read_all_buf(s, &hello, sizeof(hello));
	if (ret < 0)
		die_perror("Couldn't read server greeting");

	if (memcmp(hello.magic, PESTO_SERVER_MAGIC, sizeof(hello.magic)))
		die("Bad magic number from server");

	s_version = ntohl(hello.version);

	if (s_version > PESTO_PROTOCOL_VERSION) {
		die("Unknown server protocol version %"PRIu32" > %"PRIu32,
		    s_version, PESTO_PROTOCOL_VERSION);
	}

	/* cppcheck-suppress knownConditionTrueFalse */
	if (!s_version) {
		if (PESTO_PROTOCOL_VERSION)
			die("Unsupported experimental server protocol");
		FPRINTF(stderr,
"Warning: Using experimental protocol version, client and server must match\n");
	}

	if (ntohl(hello.pif_name_size) != PIF_NAME_SIZE) {
		die("Server has unexpected pif name size (%"
		    PRIu32" not %"PRIu32 ")",
		    ntohl(hello.pif_name_size), PIF_NAME_SIZE);
	}

	if (ntohl(hello.ifnamsiz) != IFNAMSIZ) {
		die("Server has unexpected IFNAMSIZ (%"
		    PRIu32" not %"PRIu32 ")",
		    ntohl(hello.ifnamsiz), IFNAMSIZ);
	}

	while (read_pif_conf(s, &conf))
		;

	printf("passt/pasta configuration (%s)\n", a.sun_path);
	show_conf(&conf);

	if (shutdown(s, SHUT_RDWR) < 0 || close(s) < 0)
		die_perror("Error shutting down control socket");

	exit(0);
}
