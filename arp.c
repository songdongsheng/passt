// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * arp.c - ARP implementation
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "log.h"
#include "arp.h"
#include "dhcp.h"
#include "passt.h"
#include "tap.h"

/**
 * ignore_arp() - Check if we should ignore this ARP message
 * @c:		Execution context
 * @ah:		ARP header
 * @am:		ARP message
 *
 * Return: true if the ARP message should be ignored, false otherwise
 */
static bool ignore_arp(const struct ctx *c,
		       const struct arphdr *ah, const struct arpmsg *am)
{
	if (ah->ar_hrd != htons(ARPHRD_ETHER)	||
	    ah->ar_pro != htons(ETH_P_IP)	||
	    ah->ar_hln != ETH_ALEN		||
	    ah->ar_pln != 4			||
	    ah->ar_op  != htons(ARPOP_REQUEST))
		return true;

	/* Discard announcements, but not 0.0.0.0 "probes" */
	if (memcmp(am->sip, &in4addr_any, sizeof(am->sip)) &&
	    !memcmp(am->sip, am->tip, sizeof(am->sip)))
		return true;

	/* Don't resolve the guest's assigned address, either. */
	if (!memcmp(am->tip, &c->ip4.addr, sizeof(am->tip)))
		return true;

	return false;
}

/**
 * arp() - Check if this is a supported ARP message, reply as needed
 * @c:		Execution context
 * @data:	Single packet with Ethernet buffer
 *
 * Return: 1 if handled, -1 on failure
 */
int arp(const struct ctx *c, struct iov_tail *data)
{
	union inany_addr tgt;
	struct {
		struct ethhdr eh;
		struct arphdr ah;
		struct arpmsg am;
	} __attribute__((__packed__)) resp;
	struct arphdr ah_storage;
	struct ethhdr eh_storage;
	struct arpmsg am_storage;
	const struct ethhdr *eh;
	const struct arphdr *ah;
	const struct arpmsg *am;

	eh = IOV_REMOVE_HEADER(data, eh_storage);
	ah = IOV_REMOVE_HEADER(data, ah_storage);
	am = IOV_REMOVE_HEADER(data, am_storage);
	if (!eh || !ah || !am)
		return -1;

	if (ignore_arp(c, ah, am))
		return 1;

	/* Ethernet header */
	resp.eh.h_proto = htons(ETH_P_ARP);
	memcpy(resp.eh.h_dest, eh->h_source, sizeof(resp.eh.h_dest));
	memcpy(resp.eh.h_source, c->our_tap_mac, sizeof(resp.eh.h_source));

	/* ARP header */
	resp.ah.ar_op = htons(ARPOP_REPLY);
	resp.ah.ar_hrd = ah->ar_hrd;
	resp.ah.ar_pro = ah->ar_pro;
	resp.ah.ar_hln = ah->ar_hln;
	resp.ah.ar_pln = ah->ar_pln;

	/* MAC address to return in ARP message */
	inany_from_af(&tgt, AF_INET, am->tip);
	fwd_neigh_mac_get(c, &tgt, resp.am.sha);

	/* Rest of ARP message */
	memcpy(resp.am.sip,		am->tip,	sizeof(resp.am.sip));
	memcpy(resp.am.tha,		am->sha,	sizeof(resp.am.tha));
	memcpy(resp.am.tip,		am->sip,	sizeof(resp.am.tip));

	tap_send_single(c, &resp, sizeof(resp));

	return 1;
}

/**
 * arp_send_init_req() - Send initial ARP request to retrieve guest MAC address
 * @c:		Execution context
 */
void arp_send_init_req(const struct ctx *c)
{
	struct {
		struct ethhdr eh;
		struct arphdr ah;
		struct arpmsg am;
	} __attribute__((__packed__)) req;

	/* Ethernet header */
	req.eh.h_proto = htons(ETH_P_ARP);
	memcpy(req.eh.h_dest, MAC_BROADCAST, sizeof(req.eh.h_dest));
	memcpy(req.eh.h_source, c->our_tap_mac, sizeof(req.eh.h_source));

	/* ARP header */
	req.ah.ar_op = htons(ARPOP_REQUEST);
	req.ah.ar_hrd = htons(ARPHRD_ETHER);
	req.ah.ar_pro = htons(ETH_P_IP);
	req.ah.ar_hln = ETH_ALEN;
	req.ah.ar_pln = 4;

	/* ARP message */
	memcpy(req.am.sha,	c->our_tap_mac,		sizeof(req.am.sha));
	memcpy(req.am.sip,	&c->ip4.our_tap_addr,	sizeof(req.am.sip));
	memcpy(req.am.tha,	MAC_BROADCAST,		sizeof(req.am.tha));
	memcpy(req.am.tip,	&c->ip4.addr,		sizeof(req.am.tip));

	debug("Sending initial ARP request for guest MAC address");
	tap_send_single(c, &req, sizeof(req));
}
