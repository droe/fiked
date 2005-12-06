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

#include "peer_ctx.h"
#include "vpnc/math_group.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

/* message_iv */

message_iv * message_iv_get(uint32_t id, message_iv **head)
{
	message_iv *found = NULL;
	for(message_iv *p = *head; p && !found; p = p->next) {
		if(p->id == id)
			found = p;
	}

	if(!found) {
		found = malloc(sizeof(message_iv));
		memset(found, 0, sizeof(message_iv));
		found->id = id;
		found->next = *head;
		*head = found;
	}

	return found;
}

void message_iv_free(message_iv *msg_iv)
{
	if(msg_iv->next) {
		message_iv_free(msg_iv->next);
		msg_iv->next = NULL;
	}
	if(msg_iv->iv) {
		free(msg_iv->iv);
		msg_iv->iv = NULL;
	}
	free(msg_iv);
}


/* peer_ctx */

peer_ctx * peer_ctx_get(datagram *dgm, config *cfg, peer_ctx **head)
{
	peer_ctx *found = NULL;
	for(peer_ctx *p = *head; p && !found; p = p->next) {
		if(p->peer_addr.sin_addr.s_addr == dgm->peer_addr.sin_addr.s_addr &&
			p->peer_addr.sin_port == dgm->peer_addr.sin_port)
			found = p;
	}

	if(!found) {
		found = malloc(sizeof(peer_ctx));
		memset(found, 0, sizeof(peer_ctx));
		found->peer_addr = dgm->peer_addr;
		found->next = *head;
		found->state = STATE_NEW;
		found->cfg = cfg;
		*head = found;
	}

	return found;
}

#define FREE_CTX_MEMBER(x) \
	if(ctx->x) { \
		free(ctx->x); \
		ctx->x = NULL; \
	}

void peer_ctx_clear(peer_ctx *ctx)
{
	FREE_CTX_MEMBER(ipsec_id);
	FREE_CTX_MEMBER(ipsec_secret);
	FREE_CTX_MEMBER(xauth_username);
	FREE_CTX_MEMBER(xauth_password);

	FREE_CTX_MEMBER(key);
	FREE_CTX_MEMBER(iv0);
	if(ctx->msg_iv) {
		message_iv_free(ctx->msg_iv);
		ctx->msg_iv = NULL;
	}

	if(ctx->dh_group) {
		group_free(ctx->dh_group);
		ctx->dh_group = NULL;
	}

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
}

void peer_ctx_reset(peer_ctx *ctx)
{
	peer_ctx_clear(ctx);
	memset((uint8_t *)&ctx->state, 0,
		(uint8_t *)ctx - (uint8_t *)&ctx->state + sizeof(peer_ctx));
	ctx->state = STATE_NEW;
}

void peer_ctx_free(peer_ctx *ctx)
{
	if(ctx->next) {
		peer_ctx_free(ctx->next);
		ctx->next = NULL;
	}
	FREE_CTX_MEMBER(last_dgm_hash); /* only free this on free_peer_ctx */
	peer_ctx_clear(ctx);
	free(ctx);
}
