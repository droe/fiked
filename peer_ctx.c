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

/* message_iv */

message_iv * get_message_iv(uint32_t id, message_iv **head)
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

void free_message_iv(message_iv *msg_iv)
{
	if(msg_iv->next) {
		free_message_iv(msg_iv->next);
		msg_iv->next = NULL;
	}
}


/* peer_ctx */

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
		found = malloc(sizeof(peer_ctx));
		memset(found, 0, sizeof(peer_ctx));
		found->peer_addr = dgm->peer_addr;
		found->next = head;
		found->state = STATE_NEW;
		found->cfg = cfg;
		head = found;
	}

	return found;
}

#define FREE_CTX_MEMBER(x) \
	if(ctx->x) { \
		free(ctx->x); \
		ctx->x = NULL; \
	}
void clear_peer_ctx(peer_ctx *ctx)
{
	FREE_CTX_MEMBER(ipsec_id);
	FREE_CTX_MEMBER(xauth_username);
	FREE_CTX_MEMBER(xauth_password);

	FREE_CTX_MEMBER(key);
	FREE_CTX_MEMBER(iv0);
	if(ctx->msg_iv) {
		free_message_iv(ctx->msg_iv);
		ctx->msg_iv = NULL;
	}

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
}
#undef FREE_CTX_MEMBER

void reset_peer_ctx(peer_ctx *ctx)
{
	clear_peer_ctx(ctx);

	ctx->state = STATE_NEW;
	memset(ctx->i_cookie, 0, sizeof(ctx->i_cookie));
	memset(ctx->r_cookie, 0, sizeof(ctx->r_cookie));
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
	clear_peer_ctx(ctx);
	free(ctx);
}
