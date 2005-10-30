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

#ifndef RESULTS_H
#define RESULTS_H

#include "peer_ctx.h"

void results_init(char *filename);
void results_add(peer_ctx *ctx);
void results_cleanup();

#endif /* RESULTS_H */
