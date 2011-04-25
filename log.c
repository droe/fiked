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

#include "log.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

static FILE* file = NULL;
static int quiet = 0;

void
log_init(char *filename, int q)
{
	log_cleanup();
	if (filename) {
		file = fopen(filename, "a");
		if (!file) {
			fprintf(stderr, "FATAL: cannot open file %s: %s\n", filename,
				strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	quiet = q;
}

void
log_do_printf(const char *fmt, ...)
{
	va_list ap;

	char *buf;
	va_start(ap, fmt);
	vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (file) {
		fprintf(file, "%s", buf);
	}
	if (!quiet) {
		fprintf(stdout, "%s", buf);
	}
	free(buf);
}

void
log_do_flush()
{
	if (file) {
		fflush(file);
	}
	if (!quiet) {
		fflush(stdout);
	}
}

void
log_printf(peer_ctx *ctx, const char *fmt, ...)
{
	va_list ap;
	char timestamp[1024];
	time_t epoch = time(0);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S %z",
		localtime(&epoch));

	char *buf;
	va_start(ap, fmt);
	vasprintf(&buf, fmt, ap);
	va_end(ap);

	log_do_printf("[%s] [%d] ", timestamp, getpid());
	if (ctx) {
		log_do_printf("[%s:%d] ",
			inet_ntoa(ctx->peer_addr.sin_addr),
			ntohs(ctx->peer_addr.sin_port));
	}
	log_do_printf("%s\n", buf);
	log_do_flush();
	free(buf);
}

void
log_cleanup()
{
	if (file) {
		if (file != stdout)
			fclose(file);
		file = NULL;
	}
}

