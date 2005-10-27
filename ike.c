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
 * NOTICE: This code is not suitable for implementing a genuine IKE responder!
 *         It's very likely to be any or all of: insecure, incompatible,
 *         inefficient, unstable, unportable, or outright broken.
 *         If you want genuine IKE source code, look for a proper
 *         implementation instead.
 */

/* minimum */
static inline int min(int a, int b)
{
	return (a < b) ? a : b;
}

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
}

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

	/* grab i_cookie */
	memcpy(ctx->i_cookie, ikp->i_cookie, ISAKMP_COOKIE_LENGTH);

	/* grab i_sa */
	struct isakmp_payload *tmp = sa->next;
	sa->next = NULL;
	flatten_isakmp_payload(sa, &ctx->i_sa, &ctx->i_sa_len);
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
	flatten_isakmp_payload(id, &ctx->i_id, &ctx->i_id_len);
	id->next = tmp;

	/* generate r_cookie */
	gcry_create_nonce(ctx->r_cookie, ISAKMP_COOKIE_LENGTH);

	/* generate r_nonce */
	ctx->r_nonce_len = ctx->i_nonce_len;
	ctx->r_nonce = malloc(ctx->r_nonce_len);
	gcry_create_nonce(ctx->r_nonce, ctx->r_nonce_len);

	/* set up hashing */
	ctx->md_algo = GCRY_MD_MD5; /* not sexy */
	ctx->md_len = gcry_md_get_algo_dlen(ctx->md_algo);

	/* complete dh key exchange */
	ctx->dh_group = group_get(OAKLEY_GRP_2); /* not sexy */
	ctx->dh_r_public = malloc(dh_getlen(ctx->dh_group));
	dh_create_exchange(ctx->dh_group, ctx->dh_r_public);
	ctx->dh_secret = malloc(dh_getlen(ctx->dh_group));
	dh_create_shared(ctx->dh_group, ctx->dh_secret, ctx->dh_i_public);

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

	/* payload: ke */
	p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_KE,
		ctx->dh_r_public, dh_getlen(ctx->dh_group));
	p = p->next;

	/* payload: nonce_r */
	p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_NONCE,
		ctx->r_nonce, ctx->r_nonce_len);
	p = p->next;

	/* payload: id_r */
	p->next = new_isakmp_payload(ISAKMP_PAYLOAD_ID);
	p = p->next;
	p->u.id.type = ISAKMP_IPSEC_ID_IPV4_ADDR;
	p->u.id.protocol = IPPROTO_UDP;
	p->u.id.port = IKE_PORT;
	p->u.id.length = sizeof(in_addr_t);
	p->u.id.data = malloc(p->u.id.length);
	*((in_addr_t*)p->u.id.data) = inet_addr(ctx->cfg->gateway);
	flatten_isakmp_payload(p, &ctx->r_id, &ctx->r_id_len);

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
	ctx->skeyid_e = xallocc(ctx->md_len);
	memcpy(ctx->skeyid_e, gcry_md_read(md_ctx, 0), ctx->md_len);
	gcry_md_close(md_ctx);

	/* encryption key */
	ctx->algo = GCRY_CIPHER_3DES; /* not sexy */
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

	/* initial phase 1 iv */
	gcry_md_open(&md_ctx, ctx->md_algo, 0);
	gcry_md_write(md_ctx, ctx->dh_i_public, dh_getlen(ctx->dh_group));
	gcry_md_write(md_ctx, ctx->dh_r_public, dh_getlen(ctx->dh_group));
	gcry_md_final(md_ctx);
	ctx->iv = malloc(ctx->blk_len);
	memcpy(ctx->iv, gcry_md_read(md_ctx, 0), ctx->blk_len);
	gcry_md_close(md_ctx);

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
	p->next = new_isakmp_data_payload(ISAKMP_PAYLOAD_HASH,
		ctx->r_hash, ctx->md_len);
	p = p->next;

	/* send response */
	datagram *dgm = new_datagram(0);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, 8);
	dgm->peer_addr = ctx->peer_addr;
	dgm->sockfd = ctx->cfg->sockfd;
	send_datagram(dgm);

	ctx->state = STATE_PHASE1;
}

/*
 * Decrypts the payload during phase 1.
 */
void ike_decrypt_phase1(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/* XXX */

//	ikp->u.payload = parse_isakmp_payload(payload, &data, &data_len, &reason);
}

/*
 * Process an IKE Aggressive Mode packet in STATE_PHASE1.
 * Brings us into STATE_PHASE2. (probably)
 */
void ike_do_phase1_end(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/* XXX */

	/*ctx->state = STATE_PHASE1;*/
}

/*
 * Process an IKE Informational packet.
 */
void ike_process_informational(peer_ctx *ctx, struct isakmp_packet *ikp)
{
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

		default:
			printf("[%s:%d]: unhandled informational payload type 0x%02x, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				p->type);
			break;
	}}
}

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
			printf("[%s:%d]: IKE session initiated [aggressive mode]\n",
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
			ike_decrypt_phase1(ctx, ikp);
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

/*
 * Process an incoming IKE/ISAKMP packet.
 */
void ike_process_isakmp(peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/*fprintf(stderr,
		"DEBUG: ISAKMP from %s:%d version=0x%02x type=0x%02x flags=0x%02x payload=0x%02x\n",
		inet_ntoa(ctx->peer_addr.sin_addr),
		ntohs(ctx->peer_addr.sin_port),
		ikp->isakmp_version,
		ikp->exchange_type,
		ikp->flags,
		ikp->u.payload->type);*/

	/* need some mechanism to clean out old states after some time */
	/* maybe: if r_cookie == 0, reset to STATE_NEW */

	switch(ctx->state) {
		case STATE_NEW:
			ike_process_new(ctx, ikp);
			break;

		case STATE_PHASE1:
			ike_process_phase1(ctx, ikp);
			break;

		/* XXX: STATE_PHASE2_... */
		/* XXX: more states */

		default:
			printf("[%s:%d]: unhandled state, reset state\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port));
			reset_peer_ctx(ctx);
			ike_process_new(ctx, ikp);
			break;
	}

}

