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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
void ike_process_aggressive_respond(int s, peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/* get the payloads */
	struct isakmp_payload *sa = NULL;
	struct isakmp_payload *ke = NULL;
	struct isakmp_payload *nonce = NULL;
	struct isakmp_payload *id = NULL;
	for(struct isakmp_payload *p = ikp->payload; p; p = p->next) {
	switch(p->type) {
		case ISAKMP_PAYLOAD_SA:
			/*fprintf(stderr, "ISAKMP_PAYLOAD_SA\n");*/
			sa = p;
			break;

		case ISAKMP_PAYLOAD_KE:
			/*fprintf(stderr, "ISAKMP_PAYLOAD_KE\n");*/
			ke = p;
			break;

		case ISAKMP_PAYLOAD_NONCE:
			/*fprintf(stderr, "ISAKMP_PAYLOAD_NONCE\n");*/
			nonce = p;
			break;

		case ISAKMP_PAYLOAD_ID:
			/*fprintf(stderr, "ISAKMP_PAYLOAD_ID\n");*/
			id = p;
			break;

		case ISAKMP_PAYLOAD_VID:
			/*fprintf(stderr, "ISAKMP_PAYLOAD_VID\n");*/
			/* silently ignore for now */
			break;

		default:
			printf("[%s:%d]: unhandled payload type 0x%02x in aggressive_respond, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				p->type);
			break;
	}}

	/* do we have all payloads? */
	if(!(sa && ke && nonce && id)) {
		printf("[%s:%d]: missing payload(s): sa=%p ke=%p nonce=%p id=%p in aggressive_respond, ignored\n",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port),
			(void*)sa, (void*)ke, (void*)nonce, (void*)id);
		return;
	}

	/* header */
	struct isakmp_packet *r = new_isakmp_packet();
	memcpy(r->i_cookie, ikp->i_cookie, ISAKMP_COOKIE_LENGTH);
	for(int i = 0; i < ISAKMP_COOKIE_LENGTH; i++) {
		r->r_cookie[i] = (uint8_t) random() & 0xff;
	}
	r->isakmp_version = ikp->isakmp_version;
	r->exchange_type = ikp->exchange_type;
	r->flags = 0;
	r->message_id = ikp->message_id;

	/* payload: sa */
	r->payload = new_isakmp_payload(ISAKMP_PAYLOAD_SA);
	struct isakmp_payload *p = r->payload;
	sa_populate_from(ctx, p, sa);

	/* XXX: payload: ke */
	p->next = NULL /* XXX: new_isakmp_payload() */;

	/* XXX: payload: nonce_r */
	/* XXX: payload: id_r */
	/* XXX: payload: hash_r */

	datagram *dgm = new_datagram(0);
	flatten_isakmp_packet(r, &dgm->data, &dgm->len, 8);
	dgm->peer_addr = ctx->peer_addr;
	send_datagram(s, dgm);

	ctx->state = STATE_PHASE1_RESPONDED;
}

/*
 * Process an IKE Aggressive Mode packet.
 */
void ike_process_aggressive(int s, peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/*fprintf(stderr, "ISAKMP_EXCHANGE_AGGRESSIVE\n");*/

	/* XXX: need some mechanism to clean out old states after some time */
	/* XXX: maybe: if r_cookie == 0, reset to STATE_NEW */

	switch(ctx->state) {
		case STATE_NEW:
			printf("[%s:%d]: IKE aggressive mode session initiated\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port));
			ike_process_aggressive_respond(s, ctx, ikp);
			break;

		/* XXX: case STATE_PHASE1_RESPONDED:
			ike_process_aggressive_phase1_complete(s, ctx, ikp);
			break; */

		/* XXX: STATE_PHASE1_COMPLETE */
		/* XXX: more states */

		default:
			printf("[%s:%d]: aggressive mode packet in illegal state, reset state\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port));
			ctx->state = STATE_NEW; /* does this make sense? */
			break;
	}
}

/*
 * Process an IKE Informational packet.
 */
void ike_process_informational(int s, peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/*fprintf(stderr, "ISAKMP_EXCHANGE_INFORMATIONAL\n");*/

	for(struct isakmp_payload *p = ikp->payload; p; p = p->next) {
	switch(p->type) {
		case ISAKMP_PAYLOAD_N:
			/*fprintf(stderr, "ISAKMP_PAYLOAD_N\n");*/
			if(p->u.n.type == ISAKMP_N_INVALID_PAYLOAD_TYPE) {
				printf("[%s:%d]: error from peer: invalid payload type, resetting state\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port));
					ctx->state = STATE_NEW;
			} else {
				printf("[%s:%d]: unhandled notification type 0x%02x in informational, ignored\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port),
					p->u.n.type);
			}
			break;

		default:
			printf("[%s:%d]: unhandled payload type 0x%02x in informational, ignored\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				p->type);
			break;
	}}
}

/*
 * Process an incoming IKE/ISAKMP packet.
 */
void ike_process_isakmp(int s, peer_ctx *ctx, struct isakmp_packet *ikp)
{
	/*fprintf(stderr,
		"DEBUG: ISAKMP from %s:%d version=0x%02x type=0x%02x flags=0x%02x payload=0x%02x\n",
		inet_ntoa(ctx->peer_addr.sin_addr),
		ntohs(ctx->peer_addr.sin_port),
		ikp->isakmp_version,
		ikp->exchange_type,
		ikp->flags,
		ikp->payload->type);*/

	switch(ikp->exchange_type) {
		case ISAKMP_EXCHANGE_AGGRESSIVE:
			ike_process_aggressive(s, ctx, ikp);
			break;

		case ISAKMP_EXCHANGE_INFORMATIONAL:
			ike_process_informational(s, ctx, ikp);
			break;

		default:
			printf("[%s:%d]: unhandled exchange type 0x%02x\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				ikp->exchange_type);
			break;
	}
}

