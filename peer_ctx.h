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

#ifndef PEER_CTX_H
#define PEER_CTX_H

#include "datagram.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct _peer_ctx {
	struct sockaddr_in peer_addr; /* primary key */
	struct _peer_ctx *next;
	enum {
		STATE_NEW,
		STATE_PHASE1_RESPONDED,
		STATE_PHASE1_COMPLETE,
	} state;
	uint8_t i_nonce[20];
	uint8_t r_nonce[20];
} peer_ctx;

peer_ctx * get_peer_ctx(datagram *dgm);

#endif /* PEER_CTX_H */
