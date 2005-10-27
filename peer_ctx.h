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
#include "config.h"
#include "vpnc/isakmp.h"
#include "vpnc/isakmp-pkt.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct _peer_ctx {
	struct sockaddr_in peer_addr; /* primary key */
	struct _peer_ctx *next;
	config *cfg;

	enum {
		STATE_NEW,
		STATE_PHASE1,
/*		STATE_PHASE2_INIT,*/
	} state;

	int algo;
	size_t key_len;
	size_t blk_len;
	uint8_t *key;
	uint8_t *iv;
	uint8_t *iv0;

	int md_algo;
	size_t md_len;

	struct group *dh_group;
	uint8_t *dh_i_public;
	uint8_t *dh_r_public;
	uint8_t *dh_secret;

	uint8_t *skeyid;
	uint8_t *skeyid_d;
	uint8_t *skeyid_a;
	uint8_t *skeyid_e;

	uint8_t i_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t r_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t *i_sa,    *i_id,    *r_id;
	size_t   i_sa_len, i_id_len, r_id_len;
	uint8_t *i_nonce;
	uint8_t *r_nonce;
	size_t   i_nonce_len, r_nonce_len;
	uint8_t *i_hash;
	uint8_t *r_hash;
} peer_ctx;

peer_ctx * get_peer_ctx(datagram *dgm, config *cfg);
void reset_peer_ctx(peer_ctx *ctx);
void free_peer_ctx(peer_ctx *ctx);
void destroy_peer_ctx();

#endif /* PEER_CTX_H */
