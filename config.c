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

#include "config.h"
#include <stdlib.h>
#include <string.h>

/* psk */

char * psk_get_key(char *id, psk *head)
{
	char *key = NULL;
	for(psk *p = head; p && !key; p = p->next) {
		if(!strcmp(p->id, id) || !p->next)
			key = p->key;
	}

	return key;
}

void psk_set_key(char *id, char *key, psk **head)
{
	psk *found = NULL;
	for(psk *p = *head; p && !found; p = p->next) {
		if(p->id == id)
			found = p;
	}

	if(!found) {
		found = malloc(sizeof(psk));
		memset(found, 0, sizeof(psk));
		found->id = strdup(id);
		found->next = *head;
		*head = found;
	}

	found->key = strdup(key);
}

void psk_free(psk *keys)
{
	if(keys->next) {
		psk_free(keys->next);
		keys->next = NULL;
	}
	if(keys->id) {
		free(keys->id);
		keys->id = NULL;
	}
	if(keys->key) {
		free(keys->key);
		keys->key = NULL;
	}
	free(keys);
}


/* config */

config * config_new()
{
	config *cfg = malloc(sizeof(config));
	memset(cfg, 0, sizeof(config));
	return cfg;
}

#define FREE_CFG_MEMBER(x) \
	if(cfg->x) { \
		free(cfg->x); \
		cfg->x = NULL; \
	}
void config_free(config *cfg)
{
	if(cfg->us) {
		udp_socket_free(cfg->us);
		cfg->us = NULL;
	}

	FREE_CFG_MEMBER(gateway);

	if(cfg->keys) {
		psk_free(cfg->keys);
		cfg->keys = NULL;
	}

	free(cfg);
}
#undef FREE_CFG_MEMBER
