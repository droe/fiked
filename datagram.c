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
 * 
 * $Id$
 */

#include "datagram.h"
#include "log.h"
#include "mem.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Create a new datagram instance of given size.
 * If size is 0, make it as large as supported by UDP.
 */
datagram * datagram_new(size_t size)
{
	if(size == 0)
		size = UDP_DGM_MAXSIZE;
	datagram *dgm = NULL;
	mem_allocate(&dgm, sizeof(datagram));
	memset(dgm, 0, sizeof(datagram));
	dgm->len = size;
	mem_allocate(&dgm->data, dgm->len);
	memset(dgm->data, 0, sizeof(dgm->len));
	return dgm;
}

/*
 * Free a datagram instance.
 */
void datagram_free(datagram *dgm)
{
	if(dgm) {
		mem_free(&dgm->data);
		free(dgm);
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Open a UDP socket on the given port.
 * Will quit on errors.
 */
udp_socket * udp_socket_new(uint16_t port)
{
	udp_socket *s = NULL;
	mem_allocate(&s, sizeof(udp_socket));
	s->port = port;
	s->fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(s->fd < 0) {
		fprintf(stderr, "FATAL: socket(udp) returned %d: %s (%d)\n",
			s->fd, strerror(errno), errno);
		exit(-1);
	}

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(s->port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	int ret = bind(s->fd, (struct sockaddr *)&sa, sizeof(sa));
	if(ret < 0) {
		fprintf(stderr, "FATAL: bind(%d/udp) returned %d: %s (%d)\n",
			s->port, ret, strerror(errno), errno);
		exit(-1);
	}

	return s;
}

/*
 * Close UDP socket.
 */
void udp_socket_free(udp_socket *s)
{
	if(s) {
		close(s->fd);
		free(s);
	}
}

/*
 * Receive next incoming UDP datagram on socket s.
 * Blocks until a datagram is received.
 */
datagram * udp_socket_recv(udp_socket *s)
{
	char buf[UDP_DGM_MAXSIZE];
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	int ret = recvfrom(s->fd, buf, sizeof(buf), 0,
		(struct sockaddr *)&sa, &sa_len);
	if(ret < 0) {
		log_printf(NULL, "ERROR: recvfrom(%d) returned %d: %s (%d)\n",
			s->fd, ret, strerror(errno), errno);
	}

	datagram *dgm = datagram_new(ret);
	memcpy(dgm->data, buf, dgm->len);
	dgm->peer_addr = sa;

	return dgm;
}

/*
 * Send a UDP datagram onto socket s.
 */
void udp_socket_send(udp_socket *s, datagram *dgm)
{
	int ret = sendto(s->fd, dgm->data, dgm->len, 0,
		(struct sockaddr*)&dgm->peer_addr, sizeof(dgm->peer_addr));
	if(ret < 0) {
		log_printf(NULL, "ERROR: sendto(%d to %s:%d) returned %d: %s (%d)\n",
			s->fd, inet_ntoa(dgm->peer_addr.sin_addr),
			ntohs(dgm->peer_addr.sin_port),
			ret, strerror(errno), errno);
	}
}

