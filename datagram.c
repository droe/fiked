/*
 * ISAKMP MITM for Cisco PSK+XAUTH.
 * Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
 * 
 * All rights reserved.  This is unpublished work.  Unauthorized use,
 * distribution in source or binary form, modified or unmodified, is
 * strictly prohibited.
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

void free_datagram(datagram *dgm)
{
	if(dgm) {
		if(dgm->data)
			free(dgm->data);
		free(dgm);
	}
}

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
 * Receive next incoming UDP datagram on socket s.
 * Blocks until a datagram is received.
 * Will quit on errors.
 */
datagram * receive_datagram(int s)
{
	char buf[UDP_DGM_MAXSIZE];
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	int ret = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &sa_len);
	if(ret < 0) {
		fprintf(stderr, "FATAL: recvfrom(%d) returned %d: %s (%d)\n",
			s, ret, strerror(errno), errno);
		exit(-1);
	}

	datagram *dgm = (datagram*)malloc(sizeof(datagram));
	dgm->len = ret;
	dgm->data = (uint8_t*)malloc(dgm->len);
	memcpy(dgm->data, buf, dgm->len);
	dgm->peer_addr = sa;

/*
	fprintf(stderr, "LOG: recv from %s:%d\n", inet_ntoa(dgm->peer_addr.sin_addr),
		ntohs(dgm->peer_addr.sin_port));
*/

	return dgm;
}

/*
 * Send a UDP datagram onto socket s.
 */
void send_datagram(int s, datagram *dgm)
{
	int ret = sendto(s, dgm->data, dgm->len, 0,
		(struct sockaddr*)&dgm->peer_addr, sizeof(dgm->peer_addr));
	if(ret < 0) {
		fprintf(stderr, "FATAL: sendto(%d to %s:%d) returned %d: %s (%d)\n",
			s, inet_ntoa(dgm->peer_addr.sin_addr),
			ntohs(dgm->peer_addr.sin_port),
			ret, strerror(errno), errno);
		exit(-1);
	}
}

