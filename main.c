/*
 * fiked - a fake IKE PSK+XAUTH daemon based on vpnc
 * Copyright (C) 2005,2009 Daniel Roethlisberger <daniel@roe.ch>
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

#include "bsd.h"
#include "results.h"
#include "log.h"
#include "datagram.h"
#include "peer_ctx.h"
#include "ike.h"
#include "mem.h"
#include "vpnc/isakmp-pkt.h"
#include "vpnc/isakmp.h"
#include "vpnc/math_group.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include <gcrypt.h>

#ifndef __BSD__
#include <getopt.h>
#endif

char *self;
void
usage()
{
#ifdef WITH_LIBNET
#define OPTIONS "g:k:u:l:L:rdqhV"
	fprintf(stderr, "Usage: %s [-rdqhV] -g gw -k id:psk [-k ..] [-u user] [-l file] [-L file]\n", self);
	fprintf(stderr, "\t-r\tuse raw socket: forge ip src addr to match <gateway> (disables -u)\n");
#else
#define OPTIONS "g:k:u:l:L:dqhV"
	fprintf(stderr, "Usage: %s [-dqhV] -g gw -k id:psk [-k ..] [-u user] [-l file] [-L file]\n", self);
#endif
	fprintf(stderr, "\t-d\tdetach from tty and run as a daemon (implies -q)\n");
	fprintf(stderr, "\t-q\tbe quiet, don't write anything to stdout\n");
	fprintf(stderr, "\t-h\tprint help and exit\n");
	fprintf(stderr, "\t-V\tprint version and exit\n");
	fprintf(stderr, "\t-g gw\tVPN gateway address to impersonate\n");
	fprintf(stderr, "\t-k i:k\tpre-shared key aka. group password, shared secret, prefixed\n\t\twith its group/key id (first -k sets default)\n");
	fprintf(stderr, "\t-u user\tdrop privileges to unprivileged user account\n");
	fprintf(stderr, "\t-l file\tappend results to credential log file\n");
	fprintf(stderr, "\t-L file\tverbous logging to file instead of stdout\n");
	exit(EXIT_FAILURE);
}

/*
 * Check for duplicate datagrams.
 * This is not too beautiful, but works.
 */
#define DUP_HASH_ALGO GCRY_MD_SHA1
int
duplicate(peer_ctx *ctx, datagram *dgm)
{
	int dup = 0;
	size_t hash_len = gcry_md_get_algo_dlen(DUP_HASH_ALGO);
	uint8_t *dgm_hash = NULL;
	mem_allocate(&dgm_hash, hash_len);
	gcry_md_hash_buffer(DUP_HASH_ALGO, dgm_hash, dgm->data, dgm->len);

	if (ctx->last_dgm_hash) {
		dup = !memcmp(ctx->last_dgm_hash, dgm_hash, hash_len);
		free(ctx->last_dgm_hash);
	}
	ctx->last_dgm_hash = dgm_hash;
	return dup;
}

#ifndef __BSD__
void
setproctitle(const char *fmt, ...)
{
	/* FIXME: add setproctitle replacement code for Linux here ... */
}
#endif

/*
 * Signal status to outside by setting the process title.
 * If ctx is set, logs credentials to results file.
 */
void
status(config *cfg, peer_ctx *ctx)
{
	static uint32_t count = 0;
#ifdef WITH_LIBNET
	char *raw_txt = cfg->opt_raw ? "+raw" : "";
#else
	char *raw_txt = "";
#endif
	if (!ctx) {
		log_printf(NULL, "fiked-%s started (%d/udp%s)", VERSION,
			cfg->us->port, raw_txt);
		setproctitle("[%d/udp%s] %d logins",
			cfg->us->port, raw_txt, count);
	} else {
		setproctitle("[%d/udp%s] %d logins, last: %s@%s",
			cfg->us->port, raw_txt, ++count,
			ctx->xauth_username, ctx->ipsec_id);
	}
}

/*
 * Permanently drop from root privileges to an unprivileged user account.
 * Sets the real, effective and stored user and group ID and the list of
 * ancillary groups.  This is only safe if the effective user ID is 0.
 * Returns 0 on success, -1 on failure.
 */
int
drop_to_user(const char *user)
{
	struct passwd *pw;
	int ret;

	ret = -1;
	if (!user)
		user = "nobody";

	if (!(pw = getpwnam(user)))
		goto error;

	if (initgroups(user, pw->pw_gid) == -1)
		goto error;

	if (setgid(pw->pw_gid) == -1)
		goto error;

	if (setuid(pw->pw_uid) == -1)
		goto error;

	ret = 0;
error:
	endpwent();
	return ret;
}

/*
 * Initialize libgrypt.
 * INIT_SECMEM drops privileges, so we disable secure memory if we
 * need root privileges later on (eg. for libnet to open raw sockets).
 * Since we don't put our own secrets in secure memory, we don't have
 * to worry about libgcrypt using secure memory or not.
 */
void
init_gcrypt(int need_root)
{
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	if (!gcry_check_version(GCRYPT_VERSION)) {
		fprintf(stderr, "libgcrypt version mismatch! (expected: "
			GCRYPT_VERSION ")");
		exit(EXIT_FAILURE);
	}
	if (!need_root) {
		gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	} else {
		gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	}
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

/*
 * Option processing and main loop.
 */
int
main(int argc, char *argv[])
{
	setproctitle("initializing");
	self = argv[0];
	umask(0077);

	config *cfg = config_new();
	char *logfile = NULL;
	int ch = 0;
	int opt_quiet = 0;
	int opt_daemon = 0;
	int need_root = 0;
	char *p = NULL;
	int k_valid = 0;
	char *username = NULL;
	while ((ch = getopt(argc, argv, OPTIONS)) != -1) {
		switch (ch) {
		case 'g':
			cfg->gateway = strdup(optarg);
			break;
		case 'k':
			k_valid = 0;
			for (p = optarg; *p; p++) {
				if (*p == ':') {
					*p++ = '\0';
					k_valid = 1;
					break;
				}
			}
			if (!k_valid)
				usage();
			psk_set_key(optarg, p, &cfg->keys);
			break;
		case 'u':
			username = strdup(optarg);
			break;
		case 'l':
			results_init(optarg);
			break;
		case 'L':
			logfile = strdup(optarg);
			break;
		case 'd':
			opt_quiet = 1;
			opt_daemon = 1;
			break;
#ifdef WITH_LIBNET
		case 'r':
			cfg->opt_raw = 1;
			need_root = 1;
			break;
#endif
		case 'q':
			opt_quiet = 1;
			break;
		case 'V':
			printf("fiked-%s - fake IKE PSK+XAUTH daemon based on vpnc\n", VERSION);
			printf("Copyright (C) 2005,2009 Daniel Roethlisberger <daniel@roe.ch>\n");
			printf("Licensed under the GNU General Public License, version 2 or later\n");
			printf("%s\n", URL);
			exit(EXIT_SUCCESS);
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!(cfg->gateway && cfg->keys))
		usage();

	group_init();
	test_pack_unpack();
	log_init(logfile, opt_quiet);
	cfg->us = udp_socket_new(IKE_PORT);
	init_gcrypt(need_root);
	if (opt_daemon)
		daemon(0, 0);
	if (!need_root) {
		if (getuid() != geteuid() && !username) {
			setuid(getuid());
		} else {
			drop_to_user(username);
		}
	}
	status(cfg, NULL);

	peer_ctx *peers = NULL;
	peer_ctx *ctx = NULL;
	datagram *dgm = NULL;
	int reject = 0;
	struct isakmp_packet *ikp;
	while (1) {
		dgm = udp_socket_recv(cfg->us);
		ctx = peer_ctx_get(dgm, cfg, &peers);
		if (!duplicate(ctx, dgm)) {
			ikp = parse_isakmp_packet(dgm->data, dgm->len, &reject);
			if (reject) {
				log_printf(ctx, "illegal ISAKMP packet (%d)",
					reject);
			} else {
				ike_process_isakmp(ctx, ikp);
				if (ctx->done) {
					results_add(ctx);
					status(ctx->cfg, ctx);
					ctx->done = 0;
				}
			}
			free_isakmp_packet(ikp);
		}
		datagram_free(dgm);
	}

	log_printf(NULL, "Bye.");
	results_cleanup();
	log_cleanup();
	peer_ctx_free(peers);
	config_free(cfg);
	exit(EXIT_SUCCESS);
}

