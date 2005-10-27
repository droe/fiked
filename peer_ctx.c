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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

static peer_ctx *head = NULL;

peer_ctx * get_peer_ctx(datagram *dgm, config *cfg)
{
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
	memset(ctx->i_nonce, 0, sizeof(ctx->i_nonce));
	memset(ctx->r_nonce, 0, sizeof(ctx->r_nonce));
}

void destroy_peer_ctx()
{
	free_peer_ctx(head);
	head = NULL;
}

#define FREE_CTX_MEMBER(x) \
	if(ctx->x) { \
		free(ctx->x); \
		ctx->x = NULL; \
	}
void free_peer_ctx(peer_ctx *ctx)
{
	if(ctx->next) {
		free_peer_ctx(ctx->next);
		ctx->next = NULL;
	}

	FREE_CTX_MEMBER(ipsec_id);
	FREE_CTX_MEMBER(xauth_username);
	FREE_CTX_MEMBER(xauth_password);

	FREE_CTX_MEMBER(key);
	FREE_CTX_MEMBER(iv);

	FREE_CTX_MEMBER(dh_group);
	FREE_CTX_MEMBER(dh_i_public);
	FREE_CTX_MEMBER(dh_r_public);
	FREE_CTX_MEMBER(dh_secret);

	FREE_CTX_MEMBER(skeyid);
	FREE_CTX_MEMBER(skeyid_e);
	FREE_CTX_MEMBER(skeyid_a);
	FREE_CTX_MEMBER(skeyid_d);

	FREE_CTX_MEMBER(i_sa);
	FREE_CTX_MEMBER(i_id);
	FREE_CTX_MEMBER(r_id);
	FREE_CTX_MEMBER(i_nonce);
	FREE_CTX_MEMBER(r_nonce);
	FREE_CTX_MEMBER(i_hash);
	FREE_CTX_MEMBER(r_hash);

	free(ctx);
}
#undef FREE_CTX_MEMBER
