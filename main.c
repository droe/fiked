/*
 * ISAKMP MITM for Cisco PSK+XAUTH.
 * Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
 * 
 * All rights reserved.  This is unpublished work.  Unauthorized use,
 * distribution in source or binary form, modified or unmodified, is
 * strictly prohibited.
 * 
 * $Id$
 */

#include "datagram.h"
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

#define ISAKMP_PORT	500

typedef struct _peer_ctx {
	struct sockaddr_in peer_addr; /* primary key */
	struct _peer_ctx *next;
	/* int state; */
} peer_ctx;

peer_ctx * get_peer_ctx(datagram *dgm)
{
	static peer_ctx *head = NULL;

	peer_ctx *found = NULL;
	for(peer_ctx *p = head; p && !found; p = p->next) {
		if(p->peer_addr.sin_addr.s_addr == dgm->peer_addr.sin_addr.s_addr &&
			p->peer_addr.sin_port == dgm->peer_addr.sin_port)
			found = p;
	}

	if(!found) {
		found = (peer_ctx*)malloc(sizeof(peer_ctx));
		memset(found, 0, sizeof(peer_ctx));
		found->peer_addr = dgm->peer_addr;
		found->next = head;
		head = found;
	}

	return found;
}

/*
 * Process an incoming datagram.
 */
void process_datagram(int s, datagram *dgm)
{
	peer_ctx *ctx = get_peer_ctx(dgm);

	/* XXX */
	int reject = 0;
	struct isakmp_packet *ikp = parse_isakmp_packet(dgm->data, dgm->len, &reject);

	fprintf(stderr, "DEBUG: isakmp version=0x%02x type=0x%02x flags=0x%02x payload=0x%02x\n",
		ikp->isakmp_version, ikp->exchange_type, ikp->flags, ikp->payload->type);

/*
	if(ikp->exchange_type != ISAKMP_EXCHANGE_AGGRESSIVE)
*/

/*
	send_datagram(s, dgm);
*/

	fprintf(stderr, "ERROR: process_datagram(%d from %s:%d): not implemented\n",
		dgm->len, inet_ntoa(ctx->peer_addr.sin_addr),
		ntohs(ctx->peer_addr.sin_port));

}

/*
 * Option processing and main loop.
 */
int main(int argc, char *argv[])
{

	/* XXX getopt */

	printf("ISAKMP MITM for Cisco PSK+XAUTH\n");
	printf("Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>\n");

	int sockfd = open_udp_socket(ISAKMP_PORT);
	printf("Listening on %d/udp...\n", ISAKMP_PORT);

	datagram *dgm;
	while(1) {
		dgm = receive_datagram(sockfd);
		process_datagram(sockfd, dgm);
		free_datagram(dgm);
	}

	printf("Bye.\n");
	return 0;
}

