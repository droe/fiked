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

#ifndef IKE_H
#define IKE_H

#include "peer_ctx.h"
#include "isakmp/isakmp-pkt.h"
/*
#include "isakmp/isakmp.h"
*/

#define IKE_PORT	500

void ike_process(int s, peer_ctx *ctx, struct isakmp_packet *ikp);

#endif /* IKE_H */
