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
 * 
 * $Id$
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "datagram.h"

typedef struct _psk {
	struct _psk *next;
	char *id; /* primary key */
	char *key;
} psk;

typedef struct _config {
	udp_socket *us;		/* UDP socket we listen on */
	char *gateway;		/* IP address of VPN gateway to impersonate */
	psk *keys;		/* list of pre-shared keys */
	int opt_raw;		/* use raw sockets to send packets */
} config;

char * psk_get_key(char *id, psk *head);
void psk_set_key(char *id, char *key, psk **head);
void psk_free(psk *keys);

config * config_new();
void config_free(config *cfg);

#endif /* CONFIG_H */

