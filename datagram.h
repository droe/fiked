/*
 * IKE MITM for Cisco PSK+XAUTH.
 * Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
 * 
 * All rights reserved.  This is unpublished work.  Unauthorized use,
 * distribution in source or binary form, modified or unmodified, is
 * strictly prohibited.
 * 
 * $Id$
 */

#ifndef DATAGRAM_H
#define DATAGRAM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define UDP_DGM_MAXSIZE	65507

typedef struct _datagram {
	size_t len;
	uint8_t *data;
	struct sockaddr_in peer_addr;
} datagram;

void free_datagram(datagram *dgm);
int open_udp_socket(uint16_t port);
datagram * receive_datagram(int s);
void send_datagram(int s, datagram *dgm);

#endif /* DATAGRAM_H */
