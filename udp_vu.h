// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#ifndef UDP_VU_H
#define UDP_VU_H

void udp_vu_listen_sock_data(const struct ctx *c, union epoll_ref ref,
			     const struct timespec *now);
bool udp_vu_reply_sock_data(const struct ctx *c, int s, int n,
			    flow_sidx_t tosidx);

#endif /* UDP_VU_H */
