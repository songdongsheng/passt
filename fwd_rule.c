// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * PESTO - Programmable Extensible Socket Translation Orchestrator
 *  front-end for passt(1) and pasta(1) forwarding configuration
 *
 * fwd_rule.c - Helpers for working with forwarding rule specifications
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "fwd_rule.h"
#include "lineread.h"
#include "log.h"

/* Ephemeral port range: values from RFC 6335 */
static in_port_t fwd_ephemeral_min = (1 << 15) + (1 << 14);
static in_port_t fwd_ephemeral_max = NUM_PORTS - 1;

#define PORT_RANGE_SYSCTL	"/proc/sys/net/ipv4/ip_local_port_range"

/** fwd_probe_ephemeral() - Determine what ports this host considers ephemeral
 *
 * Work out what ports the host thinks are emphemeral and record it for later
 * use by fwd_port_is_ephemeral().  If we're unable to probe, assume the range
 * recommended by RFC 6335.
 */
void fwd_probe_ephemeral(void)
{
	char *line, *tab, *end;
	struct lineread lr;
	long min, max;
	ssize_t len;
	int fd;

	fd = open(PORT_RANGE_SYSCTL, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		warn_perror("Unable to open %s", PORT_RANGE_SYSCTL);
		return;
	}

	lineread_init(&lr, fd);
	len = lineread_get(&lr, &line);
	close(fd);

	if (len < 0)
		goto parse_err;

	tab = strchr(line, '\t');
	if (!tab)
		goto parse_err;
	*tab = '\0';

	errno = 0;
	min = strtol(line, &end, 10);
	if (*end || errno)
		goto parse_err;

	errno = 0;
	max = strtol(tab + 1, &end, 10);
	if (*end || errno)
		goto parse_err;

	if (min < 0 || min >= (long)NUM_PORTS ||
	    max < 0 || max >= (long)NUM_PORTS)
		goto parse_err;

	fwd_ephemeral_min = min;
	fwd_ephemeral_max = max;

	return;

parse_err:
	warn("Unable to parse %s", PORT_RANGE_SYSCTL);
}

/**
 * fwd_port_map_ephemeral() - Mark ephemeral ports in a bitmap
 * @map:	Bitmap to update
 */
static void fwd_port_map_ephemeral(uint8_t *map)
{
	unsigned port;

	for (port = fwd_ephemeral_min; port <= fwd_ephemeral_max; port++)
		bitmap_set(map, port);
}

/**
 * fwd_rule_addr() - Return match address for a rule
 * @rule:	Forwarding rule
 *
 * Return: matching address for rule, NULL if it matches all addresses
 */
const union inany_addr *fwd_rule_addr(const struct fwd_rule *rule)
{
	if (rule->flags & FWD_DUAL_STACK_ANY)
		return NULL;

	return &rule->addr;
}

/**
 * fwd_rule_fmt() - Prettily format forwarding rule as a string
 * @rule:	Rule to format
 * @dst:	Buffer to store output (should have FWD_RULE_STRLEN bytes)
 * @size:	Size of @dst
 */
#if defined(__GNUC__) && __GNUC__ < 15
/* Workaround bug in gcc 12, 13 & 14 (at least) which gives a false positive
 * -Wformat-overflow message if this function is inlined.
 */
__attribute__((noinline))
#endif
/* cppcheck-suppress staticFunction */
const char *fwd_rule_fmt(const struct fwd_rule *rule, char *dst, size_t size)
{
	const char *percent = *rule->ifname ? "%" : "";
	const char *weak = "", *scan = "";
	char addr[INANY_ADDRSTRLEN];
	int len;

	inany_ntop(fwd_rule_addr(rule), addr, sizeof(addr));
	if (rule->flags & FWD_WEAK)
		weak = " (best effort)";
	if (rule->flags & FWD_SCAN)
		scan = " (auto-scan)";

	if (rule->first == rule->last) {
		len = snprintf(dst, size,
			       "%s [%s]%s%s:%hu  =>  %hu %s%s",
			       ipproto_name(rule->proto), addr, percent,
			       rule->ifname, rule->first, rule->to, weak, scan);
	} else {
		in_port_t tolast = rule->last - rule->first + rule->to;
		len = snprintf(dst, size,
			       "%s [%s]%s%s:%hu-%hu  =>  %hu-%hu %s%s",
			       ipproto_name(rule->proto), addr, percent,
			       rule->ifname, rule->first, rule->last,
			       rule->to, tolast, weak, scan);
	}

	if (len < 0 || (size_t)len >= size)
		return NULL;

	return dst;
}

/**
 * fwd_rules_info() - Print forwarding rules for debugging
 * @fwd:	Table to print
 */
void fwd_rules_info(const struct fwd_rule *rules, size_t count)
{
	unsigned i;

	for (i = 0; i < count; i++) {
		char buf[FWD_RULE_STRLEN];

		info("    %s", fwd_rule_fmt(&rules[i], buf, sizeof(buf)));
	}
}

/**
 * fwd_rule_conflicts() - Test if two rules conflict with each other
 * @a, @b:	Rules to test
 */
static bool fwd_rule_conflicts(const struct fwd_rule *a, const struct fwd_rule *b)
{
	if (a->proto != b->proto)
		/* Non-conflicting protocols */
		return false;

	if (!inany_matches(fwd_rule_addr(a), fwd_rule_addr(b)))
		/* Non-conflicting addresses */
		return false;

	assert(a->first <= a->last && b->first <= b->last);
	if (a->last < b->first || b->last < a->first)
		/* Port ranges don't overlap */
		return false;

	return true;
}

/**
 * fwd_rule_add() - Validate and add a rule to a forwarding table
 * @fwd:	Table to add to
 * @new:	Rule to add
 *
 * Return: 0 on success, negative error code on failure
 */
static int fwd_rule_add(struct fwd_table *fwd, const struct fwd_rule *new)
{
	/* Flags which can be set from the caller */
	const uint8_t allowed_flags = FWD_WEAK | FWD_SCAN | FWD_DUAL_STACK_ANY;
	unsigned num = (unsigned)new->last - new->first + 1;
	unsigned port, i;

	if (new->first > new->last) {
		warn("Rule has invalid port range %u-%u",
		     new->first, new->last);
		return -EINVAL;
	}
	if (!new->first) {
		warn("Forwarding rule attempts to map from port 0");
		return -EINVAL;
	}
	if (!new->to ||
	    (in_port_t)(new->to + new->last - new->first) < new->to) {
		warn("Forwarding rule attempts to map to port 0");
		return -EINVAL;
	}
	if (new->flags & ~allowed_flags) {
		warn("Rule has invalid flags 0x%hhx",
		     new->flags & ~allowed_flags);
		return -EINVAL;
	}
	if (new->flags & FWD_DUAL_STACK_ANY) {
		if (!inany_equals(&new->addr, &inany_any6)) {
			char astr[INANY_ADDRSTRLEN];

			warn("Dual stack rule has non-wildcard address %s",
			     inany_ntop(&new->addr, astr, sizeof(astr)));
			return -EINVAL;
		}
		if (!(fwd->caps & FWD_CAP_IPV4)) {
			warn("Dual stack forward, but IPv4 not enabled");
			return -EINVAL;
		}
		if (!(fwd->caps & FWD_CAP_IPV6)) {
			warn("Dual stack forward, but IPv6 not enabled");
			return -EINVAL;
		}
	} else {
		if (inany_v4(&new->addr) && !(fwd->caps & FWD_CAP_IPV4)) {
			warn("IPv4 forward, but IPv4 not enabled");
			return -EINVAL;
		}
		if (!inany_v4(&new->addr) && !(fwd->caps & FWD_CAP_IPV6)) {
			warn("IPv6 forward, but IPv6 not enabled");
			return -EINVAL;
		}
	}
	if (new->proto == IPPROTO_TCP) {
		if (!(fwd->caps & FWD_CAP_TCP)) {
			warn("Can't add TCP forwarding rule, TCP not enabled");
			return -EINVAL;
		}
	} else if (new->proto == IPPROTO_UDP) {
		if (!(fwd->caps & FWD_CAP_UDP)) {
			warn("Can't add UDP forwarding rule, UDP not enabled");
			return -EINVAL;
		}
	} else {
		warn("Unsupported protocol 0x%hhx (%s) for forwarding rule",
		     new->proto, ipproto_name(new->proto));
		return -EINVAL;
	}

	for (i = 0; i < fwd->count; i++) {
		char newstr[FWD_RULE_STRLEN], rulestr[FWD_RULE_STRLEN];

		if (!fwd_rule_conflicts(new, &fwd->rules[i]))
			continue;

		warn("Forwarding configuration conflict: %s versus %s",
		     fwd_rule_fmt(new, newstr, sizeof(newstr)),
		     fwd_rule_fmt(&fwd->rules[i], rulestr, sizeof(rulestr)));
		return -EEXIST;
	}

	if (fwd->count >= ARRAY_SIZE(fwd->rules)) {
		warn("Too many rules (maximum %u)", ARRAY_SIZE(fwd->rules));
		return -ENOSPC;
	}
	if ((fwd->sock_count + num) > ARRAY_SIZE(fwd->socks)) {
		warn("Rules require too many listening sockets (maximum %u)",
		     ARRAY_SIZE(fwd->socks));
		return -ENOSPC;
	}

	fwd->rulesocks[fwd->count] = &fwd->socks[fwd->sock_count];
	for (port = new->first; port <= new->last; port++)
		fwd->rulesocks[fwd->count][port - new->first] = -1;

	fwd->rules[fwd->count++] = *new;
	fwd->sock_count += num;
	return 0;
}

/**
 * port_range() - Represents a non-empty range of ports
 * @first:	First port number in the range
 * @last:	Last port number in the range (inclusive)
 *
 * Invariant:	@last >= @first
 */
struct port_range {
	in_port_t first, last;
};

/**
 * parse_port_range() - Parse a range of port numbers '<first>[-<last>]'
 * @s:		String to parse
 * @endptr:	Update to the character after the parsed range (similar to
 *		strtol() etc.)
 * @range:	Update with the parsed values on success
 *
 * Return: -EINVAL on parsing error, -ERANGE on out of range port
 *	   numbers, 0 on success
 */
static int parse_port_range(const char *s, const char **endptr,
			    struct port_range *range)
{
	unsigned long first, last;
	char *ep;

	last = first = strtoul(s, &ep, 10);
	if (ep == s) /* Parsed nothing */
		return -EINVAL;
	if (*ep == '-') { /* we have a last value too */
		const char *lasts = ep + 1;
		last = strtoul(lasts, &ep, 10);
		if (ep == lasts) /* Parsed nothing */
			return -EINVAL;
	}

	if ((last < first) || (last >= NUM_PORTS))
		return -ERANGE;

	range->first = first;
	range->last = last;
	*endptr = ep;

	return 0;
}

/**
 * parse_keyword() - Parse a literal keyword
 * @s:		String to parse
 * @endptr:	Update to the character after the keyword
 * @kw:		Keyword to accept
 *
 * Return: 0, if @s starts with @kw, -EINVAL if it does not
 */
static int parse_keyword(const char *s, const char **endptr, const char *kw)
{
	size_t len = strlen(kw);

	if (strlen(s) < len)
		return -EINVAL;

	if (memcmp(s, kw, len))
		return -EINVAL;

	*endptr = s + len;
	return 0;
}

/**
 * fwd_rule_range_except() - Set up forwarding for a range of ports minus a
 *                           bitmap of exclusions
 * @fwd:	Forwarding table to be updated
 * @proto:	Protocol to forward
 * @addr:	Listening address
 * @ifname:	Listening interface
 * @first:	First port to forward
 * @last:	Last port to forward
 * @exclude:	Bitmap of ports to exclude (may be NULL)
 * @to:		Port to translate @first to when forwarding
 * @flags:	Flags for forwarding entries
 */
static void fwd_rule_range_except(struct fwd_table *fwd, uint8_t proto,
				  const union inany_addr *addr,
				  const char *ifname,
				  uint16_t first, uint16_t last,
				  const uint8_t *exclude, uint16_t to,
				  uint8_t flags)
{
	struct fwd_rule rule = {
		.addr = addr ? *addr : inany_any6,
		.ifname = { 0 },
		.proto = proto,
		.flags = flags,
	};
	char rulestr[FWD_RULE_STRLEN];
	unsigned delta = to - first;
	unsigned base, i;

	if (!addr)
		rule.flags |= FWD_DUAL_STACK_ANY;
	if (ifname) {
		int ret;

		ret = snprintf(rule.ifname, sizeof(rule.ifname),
			       "%s", ifname);
		if (ret <= 0 || (size_t)ret >= sizeof(rule.ifname))
			die("Invalid interface name: %s", ifname);
	}

	for (base = first; base <= last; base++) {
		if (exclude && bitmap_isset(exclude, base))
			continue;

		for (i = base; i <= last; i++) {
			if (exclude && bitmap_isset(exclude, i))
				break;
		}

		rule.first = base;
		rule.last = i - 1;
		rule.to = base + delta;

		if (fwd_rule_add(fwd, &rule) < 0)
			goto fail;

		base = i - 1;
	}
	return;

fail:
	die("Unable to add rule %s",
	    fwd_rule_fmt(&rule, rulestr, sizeof(rulestr)));
}

/*
 * for_each_chunk - Step through delimited chunks of a string
 * @p_:		Pointer to start of each chunk (updated)
 * @ep_:	Pointer to end of each chunk (updated)
 * @s_:		String to step through
 * @sep_:	String of all allowed delimiters
 */
#define for_each_chunk(p_, ep_, s_, sep_)			\
	for ((p_) = (s_);					\
	     (ep_) = (p_) + strcspn((p_), (sep_)), *(p_);	\
	     (p_) = *(ep_) ? (ep_) + 1 : (ep_))

/**
 * fwd_rule_parse_ports() - Parse port range(s) specifier
 * @fwd:	Forwarding table to be updated
 * @proto:	Protocol to forward
 * @addr:	Listening address for forwarding
 * @ifname:	Interface name for listening
 * @spec:	Port range(s) specifier
 */
static void fwd_rule_parse_ports(struct fwd_table *fwd, uint8_t proto,
				 const union inany_addr *addr,
				 const char *ifname,
				 const char *spec)
{
	uint8_t exclude[PORT_BITMAP_SIZE] = { 0 };
	bool exclude_only = true;
	const char *p, *ep;
	uint8_t flags = 0;
	unsigned i;

	if (!strcmp(spec, "all")) {
		/* Treat "all" as equivalent to "": all non-ephemeral ports */
		spec = "";
	}

	/* Parse excluded ranges and "auto" in the first pass */
	for_each_chunk(p, ep, spec, ",") {
		struct port_range xrange;

		if (isdigit(*p)) {
			/* Include range, parse later */
			exclude_only = false;
			continue;
		}

		if (parse_keyword(p, &p, "auto") == 0) {
			if (p != ep) /* Garbage after the keyword */
				goto bad;

			if (!(fwd->caps & FWD_CAP_SCAN)) {
				die(
"'auto' port forwarding is only allowed for pasta");
			}

			flags |= FWD_SCAN;
			continue;
		}

		/* Should be an exclude range */
		if (*p != '~')
			goto bad;
		p++;

		if (parse_port_range(p, &p, &xrange))
			goto bad;
		if (p != ep) /* Garbage after the range */
			goto bad;

		for (i = xrange.first; i <= xrange.last; i++)
			bitmap_set(exclude, i);
	}

	if (exclude_only) {
		/* Exclude ephemeral ports */
		fwd_port_map_ephemeral(exclude);

		fwd_rule_range_except(fwd, proto, addr, ifname,
				      1, NUM_PORTS - 1, exclude,
				      1, flags | FWD_WEAK);
		return;
	}

	/* Now process base ranges, skipping exclusions */
	for_each_chunk(p, ep, spec, ",") {
		struct port_range orig_range, mapped_range;

		if (!isdigit(*p))
			/* Already parsed */
			continue;

		if (parse_port_range(p, &p, &orig_range))
			goto bad;

		if (*p == ':') { /* There's a range to map to as well */
			if (parse_port_range(p + 1, &p, &mapped_range))
				goto bad;
			if ((mapped_range.last - mapped_range.first) !=
			    (orig_range.last - orig_range.first))
				goto bad;
		} else {
			mapped_range = orig_range;
		}

		if (p != ep) /* Garbage after the ranges */
			goto bad;

		fwd_rule_range_except(fwd, proto, addr, ifname,
				      orig_range.first, orig_range.last,
				      exclude,
				      mapped_range.first, flags);
	}

	return;
bad:
	die("Invalid port specifier '%s'", spec);
}

/**
 * fwd_rule_parse() - Parse port configuration option
 * @optname:	Short option name, t, T, u, or U
 * @optarg:	Option argument (port specification)
 * @fwd:	Forwarding table to be updated
 */
void fwd_rule_parse(char optname, const char *optarg, struct fwd_table *fwd)
{
	union inany_addr addr_buf = inany_any6, *addr = &addr_buf;
	char buf[BUFSIZ], *spec, *ifname = NULL;
	uint8_t proto;

	if (optname == 't' || optname == 'T')
		proto = IPPROTO_TCP;
	else if (optname == 'u' || optname == 'U')
		proto = IPPROTO_UDP;
	else
		assert(0);

	if (!strcmp(optarg, "none")) {
		unsigned i;

		for (i = 0; i < fwd->count; i++) {
			if (fwd->rules[i].proto == proto) {
				die("-%c none conflicts with previous options",
					optname);
			}
		}
		return;
	}

	strncpy(buf, optarg, sizeof(buf) - 1);

	if ((spec = strchr(buf, '/'))) {
		*spec = 0;
		spec++;

		if (optname != 't' && optname != 'u')
			die("Listening address not allowed for -%c %s",
			    optname, optarg);

		if ((ifname = strchr(buf, '%'))) {
			*ifname = 0;
			ifname++;

			/* spec is already advanced one past the '/',
			 * so the length of the given ifname is:
			 * (spec - ifname - 1)
			 */
			if (spec - ifname - 1 >= IFNAMSIZ) {
				die("Interface name '%s' is too long (max %u)",
				    ifname, IFNAMSIZ - 1);
			}
		}

		if (ifname == buf + 1) {	/* Interface without address */
			addr = NULL;
		} else {
			char *p = buf;

			/* Allow square brackets for IPv4 too for convenience */
			if (*p == '[' && p[strlen(p) - 1] == ']') {
				p[strlen(p) - 1] = '\0';
				p++;
			}

			if (!inany_pton(p, addr))
				die("Bad forwarding address '%s'", p);
		}
	} else {
		spec = buf;

		addr = NULL;
	}

	if (optname == 'T' || optname == 'U') {
		assert(!addr && !ifname);

		if (!(fwd->caps & FWD_CAP_IFNAME)) {
			warn(
"SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-%c %s'",
			     optname, optarg);

			if (fwd->caps & FWD_CAP_IPV4) {
				fwd_rule_parse_ports(fwd, proto,
						     &inany_loopback4, NULL,
						     spec);
			}
			if (fwd->caps & FWD_CAP_IPV6) {
				fwd_rule_parse_ports(fwd, proto,
						     &inany_loopback6, NULL,
						     spec);
			}
			return;
		}

		ifname = "lo";
	}

	if (ifname && !(fwd->caps & FWD_CAP_IFNAME)) {
		die(
"Device binding for '-%c %s' unsupported (requires kernel 5.7+)",
		    optname, optarg);
	}

	fwd_rule_parse_ports(fwd, proto, addr, ifname, spec);
}
