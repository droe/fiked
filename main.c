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

#include "datagram.h"
#include "peer_ctx.h"
#include "ike.h"
#include "vpnc/isakmp-pkt.h"
#include "vpnc/isakmp.h"
#include "vpnc/math_group.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gcrypt.h>


char *self;
void usage()
{
	fprintf(stderr, "Usage: %s -g <gateway> -s <secret>\n", self);
	exit(-1);
}

/*
 * Check for duplicate datagrams.
 * This is not too beautiful, but works.
 */
#define DUP_HASH_ALGO GCRY_MD_SHA1
int duplicate(peer_ctx *ctx, datagram *dgm)
{
	int dup = 0;
	size_t hash_len = gcry_md_get_algo_dlen(DUP_HASH_ALGO);
	uint8_t *dgm_hash = malloc(hash_len);
	gcry_md_hash_buffer(DUP_HASH_ALGO, dgm_hash, dgm->data, dgm->len);

	if(ctx->last_dgm_hash) {
		dup = !memcmp(ctx->last_dgm_hash, dgm_hash, hash_len);
		free(ctx->last_dgm_hash);
	}
	ctx->last_dgm_hash = dgm_hash;
	return dup;
}

/*
 * Option processing and main loop.
 */
int main(int argc, char *argv[])
{
	self = argv[0];

	int ch;
	config *cfg = new_config();
	while((ch = getopt(argc, argv, "g:s:hV")) != -1) {
		switch(ch) {
		case 'g':
			cfg->gateway = malloc(strlen(optarg));
			strcpy(cfg->gateway, optarg);
			break;
		case 's':
			cfg->psk = malloc(strlen(optarg));
			strcpy(cfg->psk, optarg);
			break;
		case 'V':
			printf("IKE MITM for Cisco PSK+XAUTH\n");
			printf("Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>\n");
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(!(cfg->gateway && cfg->psk))
		usage();

	printf("Using gateway=%s secret=%s\n", cfg->gateway, cfg->psk);

	cfg->sockfd = open_udp_socket(IKE_PORT);
	printf("Listening on %d/udp...\n", IKE_PORT);

	gcry_check_version("1.1.90");
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	group_init();

	datagram *dgm;
	peer_ctx *ctx;
	int reject = 0;
	struct isakmp_packet *ikp;
	while(1) {
		dgm = receive_datagram(cfg->sockfd);
		ctx = get_peer_ctx(dgm, cfg);
		if(!duplicate(ctx, dgm)) {
			ikp = parse_isakmp_packet(dgm->data, dgm->len, &reject);
			if(reject) {
				fprintf(stderr, "[%s:%d]: illegal ISAKMP packet (%d)\n",
					inet_ntoa(ctx->peer_addr.sin_addr),
					ntohs(ctx->peer_addr.sin_port),
					reject);
			} else {
				ike_process_isakmp(ctx, ikp);
			}
			free_isakmp_packet(ikp);
		}
		free_datagram(dgm);
	}

	destroy_peer_ctx();
	free_config(cfg);
	printf("Bye.\n");
	return 0;
}

