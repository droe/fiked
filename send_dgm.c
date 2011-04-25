/*
 * fiked - a fake IKE PSK+XAUTH daemon based on vpnc
 * Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/
 */

#include "send_dgm.h"
#include "log.h"
#include "ike.h"
#ifdef WITH_LIBNET
#include <libnet.h>

/*
 * Send a UDP datagram on a raw socket.
 */
void raw_send(datagram *dgm, char *shost, uint16_t sport)
{
	static char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lnet = libnet_init(LIBNET_RAW4, NULL, errbuf);
	libnet_ptag_t udp = libnet_build_udp(
		sport, ntohs(dgm->peer_addr.sin_port),
		LIBNET_UDP_H + dgm->len, 0, dgm->data, dgm->len, lnet, 0);
	if(udp <= 0) {
		log_printf(NULL, "ERROR: cannot build UDP header: %s\n",
			libnet_geterror(lnet));
		return;
	}
	libnet_ptag_t ip = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + dgm->len,
		0, 0, 0, 64, IPPROTO_UDP, 0,
		inet_addr(shost),
		dgm->peer_addr.sin_addr.s_addr,
		NULL, 0, lnet, 0);
	if(ip <= 0) {
		log_printf(NULL, "FATAL: cannot build IP header: %s\n",
			libnet_geterror(lnet));
		return;
	}
	int ret = libnet_write(lnet);
	if(ret <= 0) {
		log_printf(NULL, "ERROR: write error: %s\n",
			libnet_geterror(lnet));
		return;
	}
	libnet_destroy(lnet);
}

#endif /* WITH_LIBNET */

/*
 * Send a datagram, using either raw sockets or UDP socket, depending on opt_raw.
 */
void send_datagram(peer_ctx *ctx, datagram *dgm)
{
#ifdef WITH_LIBNET
	if(ctx->cfg->opt_raw) {
		raw_send(dgm, ctx->cfg->gateway, IKE_PORT);
	} else {
		udp_socket_send(ctx->cfg->us, dgm);
	}
#else
	udp_socket_send(ctx->cfg->us, dgm);
#endif
}

