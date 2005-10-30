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

#include "results.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

extern int errno;
static FILE* file = NULL;

void results_init(char *filename)
{
	results_cleanup();
	file = fopen(filename, "a");
	if(!file) {
		fprintf(stderr, "FATAL: cannot open file %s: %s\n", filename,
			strerror(errno));
		exit(-1);
	}
}

void results_add(peer_ctx *ctx)
{
	if(file) {
		char timestamp[1024];
		time_t epoch = time(0);
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S %z",
			localtime(&epoch));
		fprintf(file, "%s %s %s %s %s %s %s\n", timestamp,
			ctx->cfg->gateway, ctx->ipsec_id, ctx->cfg->psk,
			inet_ntoa(ctx->peer_addr.sin_addr),
			ctx->xauth_username, ctx->xauth_password);
		fflush(file);
	}
}

void results_cleanup()
{
	if(file) {
		fclose(file);
		file = NULL;
	}
}
