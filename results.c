/*
 * fiked - a fake IKE PSK+XAUTH daemon based on vpnc
 * Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/
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
#include <errno.h>

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
			ctx->cfg->gateway, ctx->ipsec_id, ctx->ipsec_secret,
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
