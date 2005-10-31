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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Open a UDP socket on the given port.
 * Will quit on errors.
 */
int open_udp_socket(uint16_t port)
{
	int s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s < 0) {
		fprintf(stderr, "FATAL: socket() returned %d: %s (%d)\n",
			s, strerror(errno), errno);
		exit(-1);
	}

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	int ret = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if(ret < 0) {
		fprintf(stderr, "FATAL: bind(%d/udp) returned %d: %s (%d)\n",
			port, ret, strerror(errno), errno);
		exit(-1);
	}

	return s;
}

/*
 * Create a new datagram instance of given size.
 * If size is 0, make it as large as supported by UDP.
 */
datagram * datagram_new(size_t size)
{
	if(size == 0)
		size = UDP_DGM_MAXSIZE;
	datagram *dgm = (datagram*)malloc(sizeof(datagram));
	memset(dgm, 0, sizeof(datagram));
	dgm->len = size;
	dgm->data = (uint8_t*)malloc(dgm->len);
	memset(dgm->data, 0, sizeof(dgm->len));
	return dgm;
}

/*
 * Free a datagram instance.
 */
void datagram_free(datagram *dgm)
{
	if(dgm) {
		if(dgm->data)
			free(dgm->data);
		free(dgm);
	}
}

/*
 * Receive next incoming UDP datagram on socket s.
 * Blocks until a datagram is received.
 * Will quit on errors.
 */
datagram * datagram_recv(int sockfd)
{
	char buf[UDP_DGM_MAXSIZE];
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	int ret = recvfrom(sockfd, buf, sizeof(buf), 0,
		(struct sockaddr *)&sa, &sa_len);
	if(ret < 0) {
		fprintf(stderr, "FATAL: recvfrom(%d) returned %d: %s (%d)\n",
			sockfd, ret, strerror(errno), errno);
		exit(-1);
	}

	datagram *dgm = datagram_new(ret);
	memcpy(dgm->data, buf, dgm->len);
	dgm->peer_addr = sa;
	dgm->sockfd = sockfd;

	return dgm;
}

/*
 * Send a UDP datagram onto socket s.
 */
void datagram_send(datagram *dgm)
{
	int ret = sendto(dgm->sockfd, dgm->data, dgm->len, 0,
		(struct sockaddr*)&dgm->peer_addr, sizeof(dgm->peer_addr));
	if(ret < 0) {
		fprintf(stderr, "FATAL: sendto(%d to %s:%d) returned %d: %s (%d)\n",
			dgm->sockfd, inet_ntoa(dgm->peer_addr.sin_addr),
			ntohs(dgm->peer_addr.sin_port),
			ret, strerror(errno), errno);
		exit(-1);
	}
}

