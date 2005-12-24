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

#include "ike.h"
#include "datagram.h"
#include "send_dgm.h"
#include "log.h"
#include "peer_ctx.h"
#include "config.h"
#include "mem.h"
#include "vpnc/math_group.h"
#include "vpnc/dh.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

/*
 *	W A R N I N G   /   D I S C L A I M E R
 *
 *	This code is unsuitable for building a genuine IKE responder!
 *	It's very likely to be any or all of: insecure, incompatible,
 *	inefficient, unstable, unportable, or outright broken.
 *	There's hardly enough sanity checking and failure resistance.
 *	If you want genuine IKE source code, look for a proper
 *	implementation instead.  This is a quick hack to snarf XAUTH
 *	credentials from clients, not a full implementation of IKE.
 *	You've been warned.
 */



/* forward declarations */
void ike_process_new(peer_ctx *ctx, struct isakmp_packet *ikp);

/* minimum */
static inline int min(int a, int b)
{
	return (a < b) ? a : b;
}

/* vendor ids */
static const uint8_t xauth_vid[] = XAUTH_VENDOR_ID;
static const uint8_t unity_vid[] = UNITY_VENDOR_ID;



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * IKE encryption and decryption routines                                    *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Encrypts or decrypts the buffer buf.
 * Buf must already be padded to blocksize of the encryption algorithm in use.
 */
void ike_crypt_crypt(int algo, int enc, uint8_t *buf, size_t buflen,
	uint8_t *key, size_t keylen, uint8_t *iv, size_t ivlen)
{
	gcry_cipher_hd_t crypt_ctx;
	gcry_cipher_open(&crypt_ctx, algo, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(crypt_ctx, key, keylen);
	gcry_cipher_setiv(crypt_ctx, iv, ivlen);
	if(!enc)
		gcry_cipher_decrypt(crypt_ctx, buf, buflen, NULL, 0);
	else
		gcry_cipher_encrypt(crypt_ctx, buf, buflen, NULL, 0);
	gcry_cipher_close(crypt_ctx);
}

/*
 * Generic encryption/decryption routine.
 * If payload of ikp is encrypted, decrypt it, if not, encrypt it.
 * Handles phase 1 and phase 2 enc/dec, and IV generation.
 */
int ike_crypt(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/*
	 * phase 1, first:	iv = hash(i_dh_public r_dh_public)
	 * phase 1, rest:	iv = last_block_phase1
	 * phase 2, first:	iv = hash(last_block_phase1 message_id)
	 * phase 2, rest:	iv = last_block_phase2
	 */

	uint8_t *iv = NULL;
	int update_iv = 1;
	uint8_t *fp = NULL;
	size_t fp_len;
	uint8_t fp_type;
	gcry_md_hd_t md_ctx;
	int reject = 0;
	message_iv *msg_iv = NULL;

	int enc = !(ikp->flags & ISAKMP_FLAG_E);

	switch(ctx->state) {
	case STATE_PHASE1:
		/* iv0 not set means no phase 1 encrypted packets yet */
		if(!ctx->iv0) {
			/* generate initial phase 1 iv */
			gcry_md_open(&md_ctx, ctx->md_algo, 0);
			gcry_md_write(md_ctx, ctx->dh_i_public,
				dh_getlen(ctx->dh_group));
			gcry_md_write(md_ctx, ctx->dh_r_public,
				dh_getlen(ctx->dh_group));
			gcry_md_final(md_ctx);
			mem_allocate(&ctx->iv0, ctx->blk_len);
			memcpy(ctx->iv0, gcry_md_read(md_ctx, 0), ctx->blk_len);
			gcry_md_close(md_ctx);
		}
		iv = ctx->iv0;
		break;

	case STATE_PHASE2:
		/* fetch message_iv for this exchange */
		msg_iv = message_iv_get(ikp->message_id, &ctx->msg_iv);
		if(!msg_iv->iv) {
			/* generate initial phase 2 iv */
			gcry_md_open(&md_ctx, ctx->md_algo, 0);
			gcry_md_write(md_ctx, ctx->iv0, ctx->blk_len);
			gcry_md_putc(md_ctx, (ikp->message_id >> 24) & 0xFF);
			gcry_md_putc(md_ctx, (ikp->message_id >> 16) & 0xFF);
			gcry_md_putc(md_ctx, (ikp->message_id >> 8) & 0xFF);
			gcry_md_putc(md_ctx, (ikp->message_id) & 0xFF);
			gcry_md_final(md_ctx);
			mem_allocate(&msg_iv->iv, ctx->md_len);
			memcpy(msg_iv->iv, gcry_md_read(md_ctx, 0), ctx->blk_len);
			gcry_md_close(md_ctx);
		}
		iv = msg_iv->iv;
		break;

	default:
		log_printf(ctx, "ike_crypt in illegal state %d, packet ignored",
			ctx->state);
		return -1;
		break;
	}

	if(enc) {
		/* flatten and encrypt payload */
		fp_type = ikp->u.payload->type;
		flatten_isakmp_payload(ikp->u.payload, &fp, &fp_len,
			ctx->blk_len);
		ike_crypt_crypt(ctx->algo, enc, fp, fp_len,
			ctx->key, ctx->key_len, iv, ctx->blk_len);
		/* swap payload for encrypted buffer */
		free_isakmp_payload(ikp->u.payload);
		ikp->u.enc.length = fp_len;
		ikp->u.enc.data = NULL;	/* don't free */
		mem_allocate(&ikp->u.enc.data, ikp->u.enc.length);
		memcpy(ikp->u.enc.data, fp, ikp->u.enc.length);
		ikp->u.enc.type = fp_type;
		/* update IV with last cipher block */
		if(update_iv) {
			memcpy(iv, fp + fp_len - ctx->blk_len, ctx->blk_len);
		}
	} else { /* dec */
		uint8_t *newiv = NULL;
		/* copy encrypted buffer */
		fp_len = ikp->u.enc.length;
		mem_allocate(&fp, fp_len);
		memcpy(fp, ikp->u.enc.data, fp_len);
		/* store last cipher block */
		if(update_iv) {
			mem_allocate(&newiv, ctx->blk_len);
			memcpy(newiv, fp + fp_len - ctx->blk_len, ctx->blk_len);
		}
		/* decrypt encrypted buffer */
		ike_crypt_crypt(ctx->algo, enc, fp, fp_len,
			ctx->key, ctx->key_len, iv, ctx->blk_len);
		/* copy stored last cipher block to iv */
		if(update_iv) {
			memcpy(iv, newiv, ctx->blk_len);
			mem_free(&newiv);
		}
		/* swap encrypted buffer for decoded payload */
		const uint8_t *cfp = fp;
		struct isakmp_payload *pl = parse_isakmp_payload(
			ikp->u.enc.type,
			&cfp, &fp_len, &reject);
		if(reject) {
			log_printf(ctx,
				"illegal decrypted payload (%d), packet ignored",
				reject);
			mem_free(&fp);
			return reject;
		}
		free(ikp->u.enc.data);
		ikp->u.payload = pl;
	}

	mem_free(&fp);

	/* flip the "encrypted" flag */
	ikp->flags ^= ISAKMP_FLAG_E;

	return 0;
}

/*
 * Return phase 2 authentication hash for payload pl.
 * Returned hash must be freed.
 */
uint8_t * phase2_hash(peer_ctx *ctx, uint32_t message_id, struct isakmp_payload *pl)
{
	gcry_md_hd_t md_ctx;
	uint8_t *pl_flat;
	size_t pl_size;
	uint8_t *hash = NULL;
	mem_allocate(&hash, ctx->md_len);

	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid_a, ctx->md_len);

	gcry_md_putc(md_ctx, (message_id >> 24) & 0xFF);
	gcry_md_putc(md_ctx, (message_id >> 16) & 0xFF);
	gcry_md_putc(md_ctx, (message_id >> 8) & 0xFF);
	gcry_md_putc(md_ctx, (message_id) & 0xFF);

	/* XXX: nonce? */

	if(pl) {
		flatten_isakmp_payload(pl, &pl_flat, &pl_size, 1);
		gcry_md_write(md_ctx, pl_flat, pl_size);
		free(pl_flat);
	} else {
		gcry_md_putc(md_ctx, 0);
	}

	gcry_md_final(md_ctx);
	memcpy(hash, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	return hash;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Security Association payload helpers                                      *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Is this a supported SA transform?  Return 1 if yes, 0 if not.
 * We do not prioritize, instead we just select the very first supported
 * transform.
 */
int sa_transform_matches(peer_ctx* ctx, struct isakmp_payload *t)
{
	struct isakmp_attribute *enc = NULL;
	struct isakmp_attribute *keylen = NULL;
	struct isakmp_attribute *hash = NULL;
	struct isakmp_attribute *auth_method = NULL;
	struct isakmp_attribute *group_desc = NULL;
	for(struct isakmp_attribute *a = t->u.t.attributes; a; a = a->next) {
		switch(a->type) {
			case IKE_ATTRIB_ENC:
				enc = a;
				break;
			case IKE_ATTRIB_KEY_LENGTH:
				keylen = a;
				break;
			case IKE_ATTRIB_HASH:
				hash = a;
				break;
			case IKE_ATTRIB_AUTH_METHOD:
				auth_method = a;
				break;
			case IKE_ATTRIB_GROUP_DESC:
				group_desc = a;
				break;
			default:
				/* silently ignore */
				break;
		}
	}

	/* do we have all required attributes? */
	if(!(enc && hash && auth_method && group_desc)) {
		log_printf(ctx,
			"missing attribute(s): enc=%p hash=%p am=%p gd=%p",
			(void*)enc, (void*)hash, (void*)auth_method,
			(void*)group_desc);
		return 0;
	}

	/* we don't support anything other than PSK+XAUTH */
	if(auth_method->u.attr_16 != IKE_AUTH_XAUTHInitPreShared)
		return 0;

	/* choose algorithms we support */
	char *enc_txt = NULL;
	char *md_txt = NULL;
	char *dh_txt = NULL;
	switch(enc->u.attr_16) {
		case IKE_ENC_DES_CBC:
			ctx->algo = GCRY_CIPHER_DES;
			enc_txt = "DES";
			break;
		case IKE_ENC_3DES_CBC:
			ctx->algo = GCRY_CIPHER_3DES;
			enc_txt = "3DES";
			break;
		case IKE_ENC_AES_CBC:
			if(!keylen)
				return 0;
			switch(keylen->u.attr_16) {
				case 128:
					ctx->algo = GCRY_CIPHER_AES128;
					enc_txt = "AES128";
					break;
				case 192:
					ctx->algo = GCRY_CIPHER_AES192;
					enc_txt = "AES192";
					break;
				case 256:
					ctx->algo = GCRY_CIPHER_AES256;
					enc_txt = "AES256";
					break;
				default:
					return 0;
			}
			break;
		default:
			return 0;
	}
	switch(hash->u.attr_16) {
		case IKE_HASH_MD5:
			ctx->md_algo = GCRY_MD_MD5;
			md_txt = "MD5";
			break;
		case IKE_HASH_SHA:
			ctx->md_algo = GCRY_MD_SHA1;
			md_txt = "SHA1";
			break;
		default:
			return 0;
	}
	switch(group_desc->u.attr_16) {
		case IKE_GROUP_MODP_768:
			if(ctx->dh_group)
				group_free(ctx->dh_group);
			ctx->dh_group = group_get(OAKLEY_GRP_1);
			dh_txt = "DH1";
			break;
		case IKE_GROUP_MODP_1024:
			if(ctx->dh_group)
				group_free(ctx->dh_group);
			ctx->dh_group = group_get(OAKLEY_GRP_2);
			dh_txt = "DH2";
			break;
		case IKE_GROUP_MODP_1536:
			if(ctx->dh_group)
				group_free(ctx->dh_group);
			ctx->dh_group = group_get(OAKLEY_GRP_5);
			dh_txt = "DH5";
			break;
		default:
			return 0;
	}

	log_printf(ctx, "using %s %s %s", enc_txt, md_txt, dh_txt);

	/* set up lengths according to chosen algorithms */
	ctx->md_len = gcry_md_get_algo_dlen(ctx->md_algo);
	gcry_cipher_algo_info(ctx->algo, GCRYCTL_GET_BLKLEN, NULL, &(ctx->blk_len));
	gcry_cipher_algo_info(ctx->algo, GCRYCTL_GET_KEYLEN, NULL, &(ctx->key_len));

	return 1;
}

/*
 * Walk proposal SA, choose a transform, copy relevant stuff to response SA.
 */
void sa_transform_choose(peer_ctx* ctx, struct isakmp_payload *response, struct isakmp_payload *proposal)
{
	/* copy SA payload */
	*response = *proposal;
	response->u.sa.proposals = new_isakmp_payload(ISAKMP_PAYLOAD_P);

	/* copy proposals payload */
	*response->u.sa.proposals = *proposal->u.sa.proposals;
	response->u.sa.proposals->u.p.spi = NULL;
	mem_allocate(&response->u.sa.proposals->u.p.spi, response->u.sa.proposals->u.p.spi_size);
	memcpy(response->u.sa.proposals->u.p.spi,
		proposal->u.sa.proposals->u.p.spi,
		response->u.sa.proposals->u.p.spi_size);
	response->u.sa.proposals->u.p.transforms =
		new_isakmp_payload(ISAKMP_PAYLOAD_T);

	/* find matching transform */
	struct isakmp_payload *p;
	for(p = proposal->u.sa.proposals->u.p.transforms; p; p = p->next) {
		if(sa_transform_matches(ctx, p))
			break;
	}
	if(!p) {
		log_printf(ctx, "no matching algo proposal, ignoring request");
		return;
	}

	/* copy chosen transform payload */
	*response->u.sa.proposals->u.p.transforms = *p;
	response->u.sa.proposals->u.p.transforms->next = NULL;

	struct isakmp_attribute *ra = NULL;
	for(struct isakmp_attribute *pa = p->u.t.attributes; pa; pa = pa->next) {
		if(!ra) {
			/* first attribute */
			ra = response->u.sa.proposals->u.p.transforms->u.t.attributes =
				new_isakmp_attribute(pa->type, NULL);
		} else {
			/* subsequent attributes */
			ra->next = new_isakmp_attribute(pa->type, NULL);
			ra = ra->next;
		}
		*ra = *pa;
		ra->next = NULL;
		switch(ra->af) {
			case isakmp_attr_lots:
				ra->u.lots.data = NULL;		/* don't free */
				mem_allocate(&ra->u.lots.data, ra->u.lots.length);
				memcpy(ra->u.lots.data, pa->u.lots.data, ra->u.lots.length);
				break;
			case isakmp_attr_acl:
				ra->u.acl.acl_ent = NULL;	/* don't free */
				mem_allocate(&ra->u.acl.acl_ent, ra->u.acl.count * sizeof(*ra->u.acl.acl_ent));
				memcpy(ra->u.acl.acl_ent, pa->u.acl.acl_ent, ra->u.acl.count * sizeof(*ra->u.acl.acl_ent));
				break;
			default:
				/* ignore */
				break;
		}
	}
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Informational packet handler                                              *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Process an IKE Informational packet.
 * Packet must already be decrypted.
 */
void ike_process_informational(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	if(ikp->flags & ISAKMP_FLAG_E) {
		log_printf(ctx, "encrypted informational packet, reset state");
		peer_ctx_reset(ctx);
		return;
	}

	for(struct isakmp_payload *p = ikp->u.payload; p; p = p->next) {
	switch(p->type) {
	case ISAKMP_PAYLOAD_N:
		switch(p->u.n.type) {
		case ISAKMP_N_INVALID_PAYLOAD_TYPE:
			log_printf(ctx,
				"error from peer: invalid payload type, reset state");
				peer_ctx_reset(ctx);
			break;
		case ISAKMP_N_CISCO_HEARTBEAT:
			/* ignore */
			break;
		default:
			log_printf(ctx,
				"unhandled informational notification type 0x%02x, ignored",
				p->u.n.type);
			break;
		}
		break;

	case ISAKMP_PAYLOAD_D:
	case ISAKMP_PAYLOAD_HASH:
		/* a real IKE responder would check the hash and drop
		 * the packet if invalid -- we just ignore it
		 */
		break;

	default:
		log_printf(ctx,
			"unhandled informational payload type 0x%02x, ignored",
			p->type);
		break;
	}}
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Phase 2 handlers                                                          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
   IKE Initiator                                         IKE Responder
   --------------                                    -----------------
                                       <-- REQUEST(NAME="" PASSWORD="")
   REPLY(NAME="joe" PASSWORD="foobar") -->
                                                    <-- SET(STATUS=OK)
   ACK(STATUS) -->
*/

/*
 * Begin XAUTH login.
 * REQUEST(NAME="" PASSWORD="")
 */
void ike_do_phase2_xauth_begin(peer_ctx *ctx)
{
	struct isakmp_packet *r = new_isakmp_packet();
	memcpy(r->i_cookie, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	memcpy(r->r_cookie, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	r->isakmp_version = ctx->isakmp_version;
	r->exchange_type = ISAKMP_EXCHANGE_MODECFG_TRANSACTION;
	r->flags = 0;
	gcry_create_nonce((uint8_t*)&r->message_id, sizeof(r->message_id));

	r->u.payload = new_isakmp_payload(ISAKMP_PAYLOAD_HASH);

	r->u.payload->next = new_isakmp_payload(ISAKMP_PAYLOAD_MODECFG_ATTR);
	r->u.payload->next->u.modecfg.type = ISAKMP_MODECFG_CFG_REQUEST;
	r->u.payload->next->u.modecfg.attributes =
		new_isakmp_attribute(ISAKMP_XAUTH_ATTRIB_USER_NAME,
			new_isakmp_attribute(ISAKMP_XAUTH_ATTRIB_USER_PASSWORD, 0)
		);
	struct isakmp_attribute *a = r->u.payload->next->u.modecfg.attributes;
	a->af = isakmp_attr_lots;
	a->u.lots.length = 0;
	a->u.lots.data = NULL;
	a = a->next;
	a->af = isakmp_attr_lots;
	a->u.lots.length = 0;
	a->u.lots.data = NULL;

	/* send response */
	datagram *dgm = datagram_new(0);
	r->u.payload->u.hash.length = ctx->md_len;
	r->u.payload->u.hash.data =
		phase2_hash(ctx, r->message_id, r->u.payload->next);
	ike_crypt(ctx, r);
	mem_free(&dgm->data);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, ctx->blk_len);
	dgm->peer_addr = ctx->peer_addr;
	send_datagram(ctx, dgm);
	free_isakmp_packet(r);
	datagram_free(dgm);
}

/*
 * Handle XAUTH replies.
 * REPLY(NAME="joe" PASSWORD="foobar")
 */
void ike_do_phase2_xauth(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	for(struct isakmp_attribute *a =
		ikp->u.payload->next->u.modecfg.attributes; a; a = a->next) {
		switch(a->type) {
			case ISAKMP_XAUTH_ATTRIB_USER_NAME:
				mem_allocate(&ctx->xauth_username, a->u.lots.length + 1);
				memcpy(ctx->xauth_username, a->u.lots.data, a->u.lots.length);
				ctx->xauth_username[a->u.lots.length] = '\0';
				log_printf(ctx, "Xauth username: %s",
					ctx->xauth_username);
				break;
			case ISAKMP_XAUTH_ATTRIB_USER_PASSWORD:
				mem_allocate(&ctx->xauth_password, a->u.lots.length + 1);
				memcpy(ctx->xauth_password, a->u.lots.data, a->u.lots.length);
				ctx->xauth_password[a->u.lots.length] = '\0';
				log_printf(ctx, "Xauth password: %s",
					ctx->xauth_password);
				break;
			case ISAKMP_XAUTH_ATTRIB_STATUS:
				if(a->u.attr_16 == 0) {
					log_printf(ctx,
						"IKE session aborted by peer");
					peer_ctx_reset(ctx);
					return;
				}
				break;
			default:
				log_printf(ctx,
					"unhandled modecfg attr type 0x%02x, ignored",
					a->type);
				break;
		}
	}

	/* log credentials */
	ctx->done = 1;

	/* give client feedback in form of an auth failed message */
	struct isakmp_packet *r = new_isakmp_packet();
	memcpy(r->i_cookie, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	memcpy(r->r_cookie, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	r->isakmp_version = ctx->isakmp_version;
	r->exchange_type = ISAKMP_EXCHANGE_MODECFG_TRANSACTION;
	r->flags = 0;
	gcry_create_nonce((uint8_t*)&r->message_id, sizeof(r->message_id));

	r->u.payload = new_isakmp_payload(ISAKMP_PAYLOAD_HASH);

	r->u.payload->next = new_isakmp_payload(ISAKMP_PAYLOAD_MODECFG_ATTR);
	r->u.payload->next->u.modecfg.type = ISAKMP_MODECFG_CFG_SET;
	r->u.payload->next->u.modecfg.attributes =
		new_isakmp_attribute(ISAKMP_XAUTH_ATTRIB_STATUS, 0);
	struct isakmp_attribute *a = r->u.payload->next->u.modecfg.attributes;
	a->af = isakmp_attr_16;
	a->u.attr_16 = 0;

	/* send response */
	datagram *dgm = datagram_new(0);
	r->u.payload->u.hash.length = ctx->md_len;
	r->u.payload->u.hash.data =
		phase2_hash(ctx, r->message_id, r->u.payload->next);
	ike_crypt(ctx, r);
	mem_free(&dgm->data);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, ctx->blk_len);
	dgm->peer_addr = ctx->peer_addr;
	send_datagram(ctx, dgm);
	free_isakmp_packet(r);
	datagram_free(dgm);
}

/*
 * Process MODECFG packets.
 */
void ike_process_phase2_modecfg(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	switch(ikp->u.payload->next->u.modecfg.type) {
		case ISAKMP_MODECFG_CFG_REPLY:
			ike_do_phase2_xauth(ctx, ikp);
			break;

		case ISAKMP_MODECFG_CFG_ACK:
			/* final ACK(STATUS) for our SET(STATUS=FAIL) */
			log_printf(ctx, "IKE session closed");
			peer_ctx_reset(ctx);
			break;

		default:
			log_printf(ctx, "unhandled modecfg type 0x%02x, ignored",
				ikp->u.payload->next->u.modecfg.type);
			break;
	}
}

/*
 * Process an IKE packet in STATE_PHASE2.
 * Handles decryption.
 */
void ike_process_phase2(peer_ctx *ctx, struct isakmp_packet *ikp) {
	if(!(ikp->flags & ISAKMP_FLAG_E)) {
		log_printf(ctx,
			"unencrypted packet in STATE_PHASE2, reset state");
		peer_ctx_reset(ctx);
		ike_process_new(ctx, ikp);
		return;
	}

	switch(ikp->exchange_type) {
		case ISAKMP_EXCHANGE_MODECFG_TRANSACTION:
			if(!ike_crypt(ctx, ikp))
				ike_process_phase2_modecfg(ctx, ikp);
			break;

		case ISAKMP_EXCHANGE_INFORMATIONAL:
			if(!ike_crypt(ctx, ikp))
				ike_process_informational(ctx, ikp);
			break;

		default:
			log_printf(ctx,
				"unhandled exchange type 0x%02x in STATE_PHASE1, ignored",
				ikp->exchange_type);
			break;
	}
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Phase 1 handlers                                                          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Process an IKE Aggressive Mode packet in STATE_NEW.
 */
void ike_do_phase1(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/* get the payloads */
	struct isakmp_payload *sa = NULL;
	struct isakmp_payload *ke = NULL;
	struct isakmp_payload *nonce = NULL;
	struct isakmp_payload *id = NULL;
	for(struct isakmp_payload *p = ikp->u.payload; p; p = p->next) {
	switch(p->type) {
		case ISAKMP_PAYLOAD_SA:
			sa = p;
			break;

		case ISAKMP_PAYLOAD_KE:
			ke = p;
			break;

		case ISAKMP_PAYLOAD_NONCE:
			nonce = p;
			break;

		case ISAKMP_PAYLOAD_ID:
			id = p;
			break;

		case ISAKMP_PAYLOAD_VID:
			/* silently ignore for now */
			break;

		default:
			log_printf(ctx,
				"unhandled payload type 0x%02x, ignored",
				p->type);
			break;
	}}

	/* do we have all payloads? */
	if(!(sa && ke && nonce && id)) {
		log_printf(ctx,
			"missing payload(s): sa=%p ke=%p nonce=%p id=%p, ignored",
			(void*)sa, (void*)ke, (void*)nonce, (void*)id);
		return;
	}

	/* heads up: the ipsec id */
	switch(id->u.id.type) {
		case ISAKMP_IPSEC_ID_FQDN:
		case ISAKMP_IPSEC_ID_USER_FQDN:
		case ISAKMP_IPSEC_ID_KEY_ID:
			mem_allocate(&ctx->ipsec_id, id->u.id.length + 1);
			memcpy(ctx->ipsec_id, id->u.id.data, id->u.id.length);
			ctx->ipsec_id[id->u.id.length] = '\0';
			ctx->ipsec_secret = (uint8_t*) strdup(psk_get_key(
					(char*)ctx->ipsec_id,
					ctx->cfg->keys));
			log_printf(ctx, "IPSec ID: %s",
				ctx->ipsec_id);
			log_printf(ctx, "IPSec Secret: %s",
				ctx->ipsec_secret);
			break;

		default:
			log_printf(ctx,
				"IPSec ID type %d is binary, processing packet anyway",
				id->u.id.type);
			break;
	}

	/* grab proto version */
	ctx->isakmp_version = ikp->isakmp_version;

	/* grab i_cookie */
	memcpy(ctx->i_cookie, ikp->i_cookie, ISAKMP_COOKIE_LENGTH);

	/* grab i_sa */
	struct isakmp_payload *tmp = sa->next;
	sa->next = NULL;
	mem_free(&ctx->i_sa);
	flatten_isakmp_payload(sa, &ctx->i_sa, &ctx->i_sa_len, 1);
	sa->next = tmp;

	/* grab dh_i_public */
	mem_allocate(&ctx->dh_i_public, ke->u.ke.length);
	memcpy(ctx->dh_i_public, ke->u.ke.data, ke->u.ke.length);

	/* grab i_nonce */
	mem_allocate(&ctx->i_nonce, nonce->u.nonce.length);
	ctx->i_nonce_len = nonce->u.nonce.length;
	memcpy(ctx->i_nonce, nonce->u.nonce.data, nonce->u.nonce.length);

	/* grab i_id */
	tmp = id->next;
	id->next = NULL;
	mem_free(&ctx->i_id);
	flatten_isakmp_payload(id, &ctx->i_id, &ctx->i_id_len, 1);
	id->next = tmp;

	/* generate r_cookie */
	gcry_create_nonce(ctx->r_cookie, ISAKMP_COOKIE_LENGTH);

	/* generate r_nonce */
	ctx->r_nonce_len = ctx->i_nonce_len;
	mem_allocate(&ctx->r_nonce, ctx->r_nonce_len);
	gcry_create_nonce(ctx->r_nonce, ctx->r_nonce_len);

	/* header */
	struct isakmp_packet *r = new_isakmp_packet();
	memcpy(r->i_cookie, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	memcpy(r->r_cookie, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	r->isakmp_version = ikp->isakmp_version;
	r->exchange_type = ikp->exchange_type;
	r->flags = 0;
	r->message_id = ikp->message_id;

	/* payload: sa */
	r->u.payload = new_isakmp_payload(ISAKMP_PAYLOAD_SA);
	sa_transform_choose(ctx, r->u.payload, sa);
	struct isakmp_payload *p = r->u.payload;

	/* complete dh key exchange */
	mem_allocate(&ctx->dh_r_public, dh_getlen(ctx->dh_group));
	dh_create_exchange(ctx->dh_group, ctx->dh_r_public);
	mem_allocate(&ctx->dh_secret, dh_getlen(ctx->dh_group));
	dh_create_shared(ctx->dh_group, ctx->dh_secret, ctx->dh_i_public);

	/* payload: ke */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_KE,
		ctx->dh_r_public, dh_getlen(ctx->dh_group));

	/* payload: nonce_r */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_NONCE,
		ctx->r_nonce, ctx->r_nonce_len);

	/* payload: id_r */
	p = p->next = new_isakmp_payload(ISAKMP_PAYLOAD_ID);
	p->u.id.type = ISAKMP_IPSEC_ID_IPV4_ADDR;
	p->u.id.protocol = IPPROTO_UDP;
	p->u.id.port = IKE_PORT;
	p->u.id.length = sizeof(in_addr_t);
	mem_allocate(&p->u.id.data, p->u.id.length);
	*((in_addr_t*)p->u.id.data) = inet_addr(ctx->cfg->gateway);

	/* grab id_r */
	mem_free(&ctx->r_id);
	flatten_isakmp_payload(p, &ctx->r_id, &ctx->r_id_len, 1);

	/*
	 * SKEYID = hmac(pre-shared-key, Nonce_I | Nonce_R)
	 * SKEYID_e = hmac(SKEYID, SKEYID_a | g^xy | Cookie_I | Cookie_R | 2)
	 * SKEYID_a = hmac(SKEYID, SKEYID_d | g^xy | Cookie_I | Cookie_R | 1)
	 * SKEYID_d = hmac(SKEYID, g^xy | Cookie_I | Cookie_R | 0)
	 */

	gcry_md_hd_t md_ctx;

	/* generate skeyid */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->ipsec_secret, strlen((char*)ctx->ipsec_secret));
	gcry_md_write(md_ctx, ctx->i_nonce, ctx->i_nonce_len);
	gcry_md_write(md_ctx, ctx->r_nonce, ctx->r_nonce_len);
	gcry_md_final(md_ctx);
	mem_allocate(&ctx->skeyid, ctx->md_len);
	memcpy(ctx->skeyid, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* generate skeyid_e */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(md_ctx, ctx->dh_secret, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(md_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_putc(md_ctx, 0);
	gcry_md_final(md_ctx);
	mem_allocate(&ctx->skeyid_d, ctx->md_len);
	memcpy(ctx->skeyid_d, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* generate skeyid_a */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(md_ctx, ctx->skeyid_d, ctx->md_len);
	gcry_md_write(md_ctx, ctx->dh_secret, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(md_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_putc(md_ctx, 1);
	gcry_md_final(md_ctx);
	mem_allocate(&ctx->skeyid_a, ctx->md_len);
	memcpy(ctx->skeyid_a, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* generate skeyid_d */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(md_ctx, ctx->skeyid_a, ctx->md_len);
	gcry_md_write(md_ctx, ctx->dh_secret, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(md_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_putc(md_ctx, 2);
	gcry_md_final(md_ctx);
	mem_allocate(&ctx->skeyid_e, ctx->md_len);
	memcpy(ctx->skeyid_e, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* encryption key */
	mem_allocate(&ctx->key, ctx->key_len);
	if(ctx->key_len > ctx->md_len) {
		for(int i = 0; i * ctx->md_len < ctx->key_len; i++) {
			gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
			gcry_md_setkey(md_ctx, ctx->skeyid_e, ctx->md_len);
			if(i == 0)
				gcry_md_putc(md_ctx, 0);
			else
				gcry_md_write(md_ctx,
					ctx->key + (i - 1) * ctx->md_len,
					ctx->md_len);
			gcry_md_final(md_ctx);
			memcpy(ctx->key + i * ctx->md_len,
				gcry_md_read(md_ctx, 0),
				min(ctx->md_len, ctx->key_len - i * ctx->md_len));
			gcry_md_close(md_ctx);
		}
	} else {
		memcpy(ctx->key, ctx->skeyid_e, ctx->key_len);
	}

	/*
	 * HASH_I = prf(SKEYID, g^x | g^y | Cookie_I | Cookie_R | SA_I | ID_I )
	 * HASH_R = prf(SKEYID, g^y | g^x | Cookie_R | Cookie_I | SA_I | ID_R )
	 */

	/* generate i_hash */
	gcry_md_hd_t i_hash_ctx;
	gcry_md_open(&i_hash_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(i_hash_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(i_hash_ctx, ctx->dh_i_public, dh_getlen(ctx->dh_group));
	gcry_md_write(i_hash_ctx, ctx->dh_r_public, dh_getlen(ctx->dh_group));
	gcry_md_write(i_hash_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(i_hash_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(i_hash_ctx, ctx->i_sa + 4, ctx->i_sa_len - 4);
	gcry_md_write(i_hash_ctx, ctx->i_id + 4, ctx->i_id_len - 4);
	gcry_md_final(i_hash_ctx);
	mem_allocate(&ctx->i_hash, ctx->md_len);
	memcpy(ctx->i_hash, gcry_md_read(i_hash_ctx, 0), ctx->md_len);
	gcry_md_close(i_hash_ctx);

	/* generate r_hash */
	gcry_md_hd_t r_hash_ctx;
	gcry_md_open(&r_hash_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(r_hash_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(r_hash_ctx, ctx->dh_r_public, dh_getlen(ctx->dh_group));
	gcry_md_write(r_hash_ctx, ctx->dh_i_public, dh_getlen(ctx->dh_group));
	gcry_md_write(r_hash_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(r_hash_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(r_hash_ctx, ctx->i_sa + 4, ctx->i_sa_len - 4);
	gcry_md_write(r_hash_ctx, ctx->r_id + 4, ctx->r_id_len - 4);
	gcry_md_final(r_hash_ctx);
	mem_allocate(&ctx->r_hash, ctx->md_len);
	memcpy(ctx->r_hash, gcry_md_read(r_hash_ctx, 0), ctx->md_len);
	gcry_md_close(r_hash_ctx);

	/* payload: hash_r */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_HASH,
		ctx->r_hash, ctx->md_len);

	/* payload: Cisco Unity vendor id */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_VID,
		unity_vid, sizeof(unity_vid));

	/* payload: XAUTH vendor id */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_VID,
		xauth_vid, sizeof(xauth_vid));

	/* send response */
	datagram *dgm = datagram_new(0);
	mem_free(&dgm->data);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, ctx->blk_len);
	dgm->peer_addr = ctx->peer_addr;
	send_datagram(ctx, dgm);
	free_isakmp_packet(r);
	datagram_free(dgm);

	ctx->state = STATE_PHASE1;
}

/*
 * Process the last IKE Aggressive Mode packet in phase 1, containing i_hash.
 * Brings us to phase 2 (hopefully).
 */
void ike_do_phase1_end(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/* get the payloads */
	struct isakmp_payload *h = NULL;
	for(struct isakmp_payload *p = ikp->u.payload; p; p = p->next) {
	switch(p->type) {
		case ISAKMP_PAYLOAD_HASH:
			h = p;
			break;

		case ISAKMP_PAYLOAD_N:
		case ISAKMP_PAYLOAD_VID:
			/* silently ignore for now */
			break;

		default:
			log_printf(ctx,
				"unhandled payload type 0x%02x, ignored",
				p->type);
			break;
	}}

	/* do we have all payloads? */
	if(!h) {
		log_printf(ctx, "missing payload: h=%p, ignored", (void*)h);
		return;
	}

	/* verify hash */
	if(h->u.hash.length != ctx->md_len ||
		memcmp(h->u.hash.data, ctx->i_hash, ctx->md_len)) {
		log_printf(ctx, "IKE phase 1 auth failed (i_hash mismatch)");
		return;
	}

	log_printf(ctx, "IKE phase 1 complete, entering phase 2");

	ctx->state = STATE_PHASE2;
	ike_do_phase2_xauth_begin(ctx);
}

/*
 * Process an IKE packet in STATE_PHASE1.
 */
void ike_process_phase1(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	if(!(ikp->flags & ISAKMP_FLAG_E)) {
		log_printf(ctx, "unencrypted packet in STATE_PHASE1, reset state");
		peer_ctx_reset(ctx);
		ike_process_new(ctx, ikp);
		return;
	}

	switch(ikp->exchange_type) {
		case ISAKMP_EXCHANGE_AGGRESSIVE:
			if(!ike_crypt(ctx, ikp))
				ike_do_phase1_end(ctx, ikp);
			break;

		case ISAKMP_EXCHANGE_INFORMATIONAL:
			ike_process_informational(ctx, ikp);
			break;

		default:
			log_printf(ctx,
				"unhandled exchange type 0x%02x in STATE_PHASE1, ignored",
				ikp->exchange_type);
			break;
	}
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Phase 0 handler                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* phase 0 is actually phase 1 before the key exchange is complete */

/*
 * Process an IKE packet in STATE_NEW.
 */
void ike_process_new(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	if(ikp->flags & ISAKMP_FLAG_E) {
		log_printf(ctx, "encrypted packet in STATE_NEW, ignored");
		return;
	}

	switch(ikp->exchange_type) {
		case ISAKMP_EXCHANGE_AGGRESSIVE:
			log_printf(ctx, "IKE session initiated");
			ike_do_phase1(ctx, ikp);
			break;
/*
		case ISAKMP_EXCHANGE_MAIN:
			log_printf(ctx, "IKE session initiated (main mode)");
			ike_do_phase1_main1(ctx, ikp);
			break;
*/
		case ISAKMP_EXCHANGE_INFORMATIONAL:
			ike_process_informational(ctx, ikp);
			break;

		default:
			log_printf(ctx,
				"unhandled exchange type 0x%02x in STATE_NEW, ignored",
				ikp->exchange_type);
			break;
	}
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Main packet handler                                                       *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Process an incoming IKE/ISAKMP packet.
 */
void ike_process_isakmp(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/*
	 * need some (simple) mechanism to clean out old states after
	 * some time, maybe: if r_cookie == 0, reset to STATE_NEW
	 */

	switch(ctx->state) {
		case STATE_NEW:
			ike_process_new(ctx, ikp);
			break;

		case STATE_PHASE1:
			ike_process_phase1(ctx, ikp);
			break;

		case STATE_PHASE2:
			ike_process_phase2(ctx, ikp);
			break;

		default:
			log_printf(ctx, "unhandled state, reset state");
			peer_ctx_reset(ctx);
			ike_process_new(ctx, ikp);
			break;
	}

}

