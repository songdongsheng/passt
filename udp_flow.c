/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * UDP flow tracking functions
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "util.h"
#include "passt.h"
#include "flow_table.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */

/**
 * udp_at_sidx() - Get UDP specific flow at given sidx
 * @sidx:    Flow and side to retrieve
 *
 * Return: UDP specific flow at @sidx, or NULL of @sidx is invalid.  Asserts if
 *         the flow at @sidx is not FLOW_UDP.
 */
struct udp_flow *udp_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_UDP);
	return &flow->udp;
}

/*
 * udp_flow_close() - Close and clean up UDP flow
 * @c:		Execution context
 * @uflow:	UDP flow
 */
void udp_flow_close(const struct ctx *c, struct udp_flow *uflow)
{
	unsigned sidei;

	if (uflow->closed)
		return; /* Nothing to do */

	flow_foreach_sidei(sidei) {
		flow_hash_remove(c, FLOW_SIDX(uflow, sidei));
		if (uflow->s[sidei] >= 0) {
			/* The listening socket needs to stay in epoll, but the
			 * flow specific one needs to be removed */
			if (sidei == TGTSIDE)
				epoll_del(c, uflow->s[sidei]);
			close(uflow->s[sidei]);
			uflow->s[sidei] = -1;
		}
	}

	uflow->closed = true;
}

/**
 * udp_flow_sock() - Create, bind and connect a flow specific UDP socket
 * @c:		Execution context
 * @uflow:	UDP flow to open socket for
 * @sidei:	Side of @uflow to open socket for
 *
 * Return: fd of new socket on success, -ve error code on failure
 */
static int udp_flow_sock(const struct ctx *c,
			 const struct udp_flow *uflow, unsigned sidei)
{
	const struct flowside *side = &uflow->f.side[sidei];
	struct mmsghdr discard[UIO_MAXIOV] = { 0 };
	uint8_t pif = uflow->f.pif[sidei];
	union {
		flow_sidx_t sidx;
		uint32_t data;
	} fref = { .sidx = FLOW_SIDX(uflow, sidei) };
	int rc, s;

	s = flowside_sock_l4(c, EPOLL_TYPE_UDP_REPLY, pif, side, fref.data);
	if (s < 0) {
		flow_dbg_perror(uflow, "Couldn't open flow specific socket");
		return s;
	}

	if (flowside_connect(c, s, pif, side) < 0) {
		rc = -errno;
		flow_dbg_perror(uflow, "Couldn't connect flow socket");
		return rc;
	}

	/* It's possible, if unlikely, that we could receive some unrelated
	 * packets in between the bind() and connect() of this socket.  For now
	 * we just discard these.
	 *
	 * FIXME: Redirect these to an appropriate handler
	 */
	rc = recvmmsg(s, discard, ARRAY_SIZE(discard), MSG_DONTWAIT, NULL);
	if (rc >= ARRAY_SIZE(discard)) {
		flow_dbg(uflow, "Too many (%d) spurious reply datagrams", rc);
		return -E2BIG;
	}

	if (rc > 0) {
		flow_trace(uflow, "Discarded %d spurious reply datagrams", rc);
	} else if (errno != EAGAIN) {
		rc = -errno;
		flow_perror(uflow, "Unexpected error discarding datagrams");
		return rc;
	}

	return s;
}

/**
 * udp_flow_new() - Common setup for a new UDP flow
 * @c:		Execution context
 * @flow:	Initiated flow
 * @s_ini:	Initiating socket (or -1)
 * @now:	Timestamp
 *
 * Return: UDP specific flow, if successful, NULL on failure
 */
static flow_sidx_t udp_flow_new(const struct ctx *c, union flow *flow,
				int s_ini, const struct timespec *now)
{
	struct udp_flow *uflow = NULL;
	unsigned sidei;

	if (!flow_target(c, flow, IPPROTO_UDP))
		goto cancel;

	uflow = FLOW_SET_TYPE(flow, FLOW_UDP, udp);
	uflow->ts = now->tv_sec;
	uflow->s[INISIDE] = uflow->s[TGTSIDE] = -1;

	if (s_ini >= 0) {
		/* When using auto port-scanning the listening port could go
		 * away, so we need to duplicate the socket
		 */
		uflow->s[INISIDE] = fcntl(s_ini, F_DUPFD_CLOEXEC, 0);
		if (uflow->s[INISIDE] < 0) {
			flow_perror(uflow,
				    "Couldn't duplicate listening socket");
			goto cancel;
		}
	}

	if (pif_is_socket(flow->f.pif[TGTSIDE]))
		if ((uflow->s[TGTSIDE] = udp_flow_sock(c, uflow, TGTSIDE)) < 0)
			goto cancel;

	/* Tap sides always need to be looked up by hash.  Socket sides don't
	 * always, but sometimes do (receiving packets on a socket not specific
	 * to one flow).  Unconditionally hash both sides so all our bases are
	 * covered
	 */
	flow_foreach_sidei(sidei)
		flow_hash_insert(c, FLOW_SIDX(uflow, sidei));

	FLOW_ACTIVATE(uflow);

	return FLOW_SIDX(uflow, TGTSIDE);

cancel:
	if (uflow)
		udp_flow_close(c, uflow);
	flow_alloc_cancel(flow);
	return FLOW_SIDX_NONE;
}

/**
 * udp_flow_from_sock() - Find or create UDP flow for "listening" socket
 * @c:		Execution context
 * @ref:	epoll reference of the receiving socket
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @now:	Timestamp
 *
 * #syscalls fcntl arm:fcntl64 ppc64:fcntl64|fcntl i686:fcntl64
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
flow_sidx_t udp_flow_from_sock(const struct ctx *c, union epoll_ref ref,
			       const union sockaddr_inany *s_in,
			       const struct timespec *now)
{
	const struct flowside *ini;
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	ASSERT(ref.type == EPOLL_TYPE_UDP_LISTEN);

	sidx = flow_lookup_sa(c, IPPROTO_UDP, ref.udp.pif, s_in, ref.udp.port);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sastr[SOCKADDR_STRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s",
		      pif_name(ref.udp.pif),
		      sockaddr_ntop(s_in, sastr, sizeof(sastr)));
		return FLOW_SIDX_NONE;
	}

	ini = flow_initiate_sa(flow, ref.udp.pif, s_in, ref.udp.port);

	if (!inany_is_unicast(&ini->eaddr) ||
	    ini->eport == 0 || ini->oport == 0) {
		/* In principle ini->oddr also must be specified, but when we've
		 * been initiated from a socket bound to 0.0.0.0 or ::, we don't
		 * know our address, so we have to leave it unpopulated.
		 */
		flow_err(flow, "Invalid endpoint on UDP recvfrom()");
		flow_alloc_cancel(flow);
		return FLOW_SIDX_NONE;
	}

	return udp_flow_new(c, flow, ref.fd, now);
}

/**
 * udp_flow_from_tap() - Find or create UDP flow for tap packets
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address on guest side
 * @daddr:	Destination address guest side
 * @srcport:	Source port on guest side
 * @dstport:	Destination port on guest side
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
flow_sidx_t udp_flow_from_tap(const struct ctx *c,
			      uint8_t pif, sa_family_t af,
			      const void *saddr, const void *daddr,
			      in_port_t srcport, in_port_t dstport,
			      const struct timespec *now)
{
	const struct flowside *ini;
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	ASSERT(pif == PIF_TAP);

	sidx = flow_lookup_af(c, IPPROTO_UDP, pif, af, saddr, daddr,
			      srcport, dstport);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sstr[INET6_ADDRSTRLEN], dstr[INET6_ADDRSTRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s:%hu -> %s:%hu",
		      pif_name(pif),
		      inet_ntop(af, saddr, sstr, sizeof(sstr)), srcport,
		      inet_ntop(af, daddr, dstr, sizeof(dstr)), dstport);
		return FLOW_SIDX_NONE;
	}

	ini = flow_initiate_af(flow, PIF_TAP, af, saddr, srcport,
			       daddr, dstport);

	if (inany_is_unspecified(&ini->eaddr) || ini->eport == 0 ||
	    inany_is_unspecified(&ini->oaddr) || ini->oport == 0) {
		flow_dbg(flow, "Invalid endpoint on UDP packet");
		flow_alloc_cancel(flow);
		return FLOW_SIDX_NONE;
	}

	return udp_flow_new(c, flow, -1, now);
}

/**
 * udp_flow_defer() - Deferred per-flow handling (clean up aborted flows)
 * @uflow:	Flow to handle
 *
 * Return: true if the connection is ready to free, false otherwise
 */
bool udp_flow_defer(const struct udp_flow *uflow)
{
	return uflow->closed;
}

/**
 * udp_flow_timer() - Handler for timed events related to a given flow
 * @c:		Execution context
 * @uflow:	UDP flow
 * @now:	Current timestamp
 *
 * Return: true if the flow is ready to free, false otherwise
 */
bool udp_flow_timer(const struct ctx *c, struct udp_flow *uflow,
		    const struct timespec *now)
{
	if (now->tv_sec - uflow->ts <= UDP_CONN_TIMEOUT)
		return false;

	udp_flow_close(c, uflow);
	return true;
}
