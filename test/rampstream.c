// SPDX-License-Identifier: GPL-2.0-or-later

/* rampstream - Generate a check and stream of bytes in a ramp pattern
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* Length of the repeating ramp.  This is a deliberately not a "round" number so
 * that we're very likely to misalign with likely block or chunk sizes of the
 * transport.  That means we'll detect gaps in the stream, even if they occur
 * neatly on block boundaries.  Specifically this is the largest 8-bit prime. */
#define RAMPLEN		251

#define INTERVAL	10000

#define	ARRAY_SIZE(a)	((int)(sizeof(a) / sizeof((a)[0])))

#define die(...)						\
	do {							\
		fprintf(stderr, "rampstream: " __VA_ARGS__);	\
		exit(1);					\
	} while (0)

static void usage(void)
{
	die("Usage:\n"
	    "  rampstream send <number>\n"
	    "    Generate a ramp pattern of bytes on stdout, repeated <number>\n"
	    "    times\n"
	    "  rampstream check <number>\n"
	    "    Check a ramp pattern of bytes on stdin, repeater <number>\n"
	    "    times\n");
}

static void ramp_send(unsigned long long num, const uint8_t *ramp)
{
	unsigned long long i;

	for (i = 0; i < num; i++) {
		int off = 0;
		ssize_t rc;

		if (i % INTERVAL == 0)
			fprintf(stderr, "%llu...\r", i);

		while (off < RAMPLEN) {
			rc = write(1, ramp + off, RAMPLEN - off);
			if (rc < 0) {
				if (errno == EINTR ||
				    errno == EAGAIN ||
				    errno == EWOULDBLOCK)
					continue;
				die("Error writing ramp: %s\n",
				    strerror(errno));
			}
			if (rc == 0)
				die("Zero length write\n");
			off += rc;
		}
	}
}

static void ramp_check(unsigned long long num, const uint8_t *ramp)
{
	unsigned long long i;

	for (i = 0; i < num; i++) {
		uint8_t buf[RAMPLEN];
		int off = 0;
		ssize_t rc;

		if (i % INTERVAL == 0)
			fprintf(stderr, "%llu...\r", i);
		
		while (off < RAMPLEN) {
			rc = read(0, buf + off, RAMPLEN - off);
			if (rc < 0) {
				if (errno == EINTR ||
				    errno == EAGAIN ||
				    errno == EWOULDBLOCK)
					continue;
				die("Error reading ramp: %s\n",
				    strerror(errno));
			}
			if (rc == 0)
				die("Unexpected EOF, ramp %llu, byte %d\n",
				    i, off);
			off += rc;
		}

		if (memcmp(buf, ramp, sizeof(buf)) != 0) {
			int j, k;

			for (j = 0; j < RAMPLEN; j++)
				if (buf[j] != ramp[j])
					break;
			for (k = j; k < RAMPLEN && k < j + 16; k++)
				fprintf(stderr,
					"Byte %d: expected 0x%02x, got 0x%02x\n",
					k, ramp[k], buf[k]);
			die("Data mismatch, ramp %llu, byte %d\n", i, j);
		}
	}
}

int main(int argc, char *argv[])
{
	const char *subcmd = argv[1];
	unsigned long long num;
	uint8_t ramp[RAMPLEN];
	char *e;
	int i;

	if (argc < 2)
		usage();

	errno = 0;
	num = strtoull(argv[2], &e, 0);
	if (*e || errno)
		usage();

	/* Initialize the ramp block */
	for (i = 0; i < RAMPLEN; i++)
		ramp[i] = i;

	if (strcmp(subcmd, "send") == 0)
		ramp_send(num, ramp);
	else if (strcmp(subcmd, "check") == 0)
		ramp_check(num, ramp);
	else
		usage();

	exit(0);
}
