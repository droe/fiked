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

#ifndef PEER_CTX_H
#define PEER_CTX_H

#include "datagram.h"
#include "config.h"
#include "vpnc/isakmp.h"
#include "vpnc/isakmp-pkt.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct _message_iv {
	struct _message_iv *next;
	uint32_t id; /* primary key */
	uint8_t *iv;
} message_iv;

typedef struct _peer_ctx {
	/* bookkeeping */
	struct _peer_ctx *next;
	struct sockaddr_in peer_addr; /* primary key */

	/* pointer to global configuration */
	config *cfg;

	/* hash of last received datagram */
	uint8_t *last_dgm_hash;

	/* internal FSM states */
	enum {
		STATE_NEW,
		STATE_PHASE1,
		STATE_PHASE2
	} state;

	/* the interesting stuff */
	uint8_t *ipsec_id;
	uint8_t *xauth_username;
	uint8_t *xauth_password;

	/* IKE: symmetrical crypto */
	int algo;
	size_t key_len;
	size_t blk_len;
	uint8_t *key;
	uint8_t *iv0;
	message_iv *msg_iv;

	/* IKE: message digest */
	int md_algo;
	size_t md_len;

	/* IKE: Diffie-Hellman */
	struct group *dh_group;
	uint8_t *dh_i_public;
	uint8_t *dh_r_public;
	uint8_t *dh_secret;

	/* IKE: intermediate key material */
	uint8_t *skeyid;
	uint8_t *skeyid_d;
	uint8_t *skeyid_a;
	uint8_t *skeyid_e;

	/* IKE: header fields */
	uint8_t i_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t r_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t isakmp_version;

	/* IKE: phase 1 payloads */
	uint8_t *i_sa,    *i_id,    *r_id;
	size_t   i_sa_len, i_id_len, r_id_len;
	uint8_t *i_nonce;
	uint8_t *r_nonce;
	size_t   i_nonce_len, r_nonce_len;
	uint8_t *i_hash;
	uint8_t *r_hash;
} peer_ctx;

peer_ctx * get_peer_ctx(datagram *dgm, config *cfg); /* XXX: non-singular */
void reset_peer_ctx(peer_ctx *ctx);
void free_peer_ctx(peer_ctx *ctx);
void destroy_peer_ctx();

message_iv * get_message_iv(uint32_t id, message_iv **head);
void free_message_iv(message_iv *msg_iv);

#endif /* PEER_CTX_H */
