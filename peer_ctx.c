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

#include "peer_ctx.h"
#include "vpnc/isakmp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

peer_ctx * get_peer_ctx(datagram *dgm, config *cfg)
{
	static peer_ctx *head = NULL;

	peer_ctx *found = NULL;
	for(peer_ctx *p = head; p && !found; p = p->next) {
		if(p->peer_addr.sin_addr.s_addr == dgm->peer_addr.sin_addr.s_addr &&
			p->peer_addr.sin_port == dgm->peer_addr.sin_port)
			found = p;
	}

	if(!found) {
		found = (peer_ctx*)malloc(sizeof(peer_ctx));
		memset(found, 0, sizeof(peer_ctx));
		found->peer_addr = dgm->peer_addr;
		found->next = head;
		found->state = STATE_NEW;
		found->cfg = cfg;
		head = found;
	}

	return found;
}

void reset_peer_ctx(peer_ctx *ctx)
{
	ctx->state = STATE_NEW;
	memset(ctx->i_nonce, 0, ISAKMP_NONCE_LENGTH);
	memset(ctx->r_nonce, 0, ISAKMP_NONCE_LENGTH);
}

