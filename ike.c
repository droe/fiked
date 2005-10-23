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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ike_process(int s, peer_ctx *ctx, struct isakmp_packet *ikp)
{

	fprintf(stderr, "DEBUG: isakmp version=0x%02x type=0x%02x flags=0x%02x payload=0x%02x\n",
		ikp->isakmp_version, ikp->exchange_type, ikp->flags, ikp->payload->type);

	fprintf(stderr, "ERROR: ike_process(from %s:%d): not implemented\n",
		inet_ntoa(ctx->peer_addr.sin_addr),
		ntohs(ctx->peer_addr.sin_port));

/*
	if(ikp->exchange_type != ISAKMP_EXCHANGE_AGGRESSIVE)
*/

/*
	send_datagram(s, dgm);
*/

}
