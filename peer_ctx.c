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

void free_peer_ctx(peer_ctx *ctx)
{
	if(ctx->next) {
		free_peer_ctx(ctx->next);
		ctx->next = NULL;
	}
	if(ctx->dh_group) {
		free(ctx->dh_group);
		ctx->dh_group = NULL;
	}
	if(ctx->dh_i_public) {
		free(ctx->dh_i_public);
		ctx->dh_i_public = NULL;
	}
	if(ctx->dh_r_public) {
		free(ctx->dh_r_public);
		ctx->dh_r_public = NULL;
	}
	if(ctx->dh_secret) {
		free(ctx->dh_secret);
		ctx->dh_secret = NULL;
	}
	if(ctx->i_sa) {
		free(ctx->i_sa);
		ctx->i_sa = NULL;
	}
	if(ctx->i_id) {
		free(ctx->i_id);
		ctx->i_id = NULL;
	}
	if(ctx->r_id) {
		free(ctx->r_id);
		ctx->r_id = NULL;
	}
	if(ctx->i_hash) {
		free(ctx->i_hash);
		ctx->i_hash = NULL;
	}
	if(ctx->r_hash) {
		free(ctx->r_hash);
		ctx->r_hash = NULL;
	}
	if(ctx->skeyid) {
		free(ctx->skeyid);
		ctx->skeyid = NULL;
	}
	free(ctx);
}

