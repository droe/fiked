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
#include "isakmp/isakmp-pkt.h"
#include "isakmp/isakmp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Option processing and main loop.
 */
int main(int argc, char *argv[])
{
	srandomdev();

	/* XXX: getopt */

	printf("IKE MITM for Cisco PSK+XAUTH\n");
	/*printf("Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>\n");*/

	int sockfd = open_udp_socket(IKE_PORT);
	printf("Listening on %d/udp...\n", IKE_PORT);

	datagram *dgm;
	peer_ctx *ctx;
	int reject = 0;
	struct isakmp_packet *ikp;
	while(1) {
		dgm = receive_datagram(sockfd);
		ctx = get_peer_ctx(dgm);
		ikp = parse_isakmp_packet(dgm->data, dgm->len, &reject);
		if(reject) {
			fprintf(stderr, "[%s:%d]: illegal ISAKMP packet (%d)\n",
				inet_ntoa(ctx->peer_addr.sin_addr),
				ntohs(ctx->peer_addr.sin_port),
				reject);
		} else {
			ike_process_isakmp(sockfd, ctx, ikp);
		}
		free_datagram(dgm);
	}

	printf("Bye.\n");
	return 0;
}

