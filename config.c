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
	FREE_CFG_MEMBER(gateway);
	FREE_CFG_MEMBER(psk);
}
#undef FREE_CFG_MEMBER
