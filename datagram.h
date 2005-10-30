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
	int sockfd;
} datagram;

datagram * new_datagram(size_t size);
void free_datagram(datagram *dgm);
int open_udp_socket(uint16_t port);
datagram * receive_datagram(int sockfd);
void send_datagram(datagram *dgm);

#endif /* DATAGRAM_H */
