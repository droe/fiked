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

#ifndef CONFIG_H
#define CONFIG_H

typedef struct _config {
	int sockfd;	/* UDP socket we listen on */
	char *gateway;	/* IP address of VPN gateway to impersonate */
	char *psk;	/* pre-shared key */
} config;

config * new_config();
void free_config(config *cfg);

#endif /* CONFIG_H */
