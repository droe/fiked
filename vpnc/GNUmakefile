# fiked - a fake IKE PSK+XAUTH daemon based on vpnc
# Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, see http://www.gnu.org/copyleft/
# 
# $Id$

# inherit from parent
CC?=gcc
CFLAGS?=-g -Wall -pedantic
LDFLAGS?=-g -Wall -pedantic
CSTD?=-std=c99
COPTS?=-I/usr/local/include
LDOPTS?=-L/usr/local/lib
LIBS?=-lgcrypt

all: libvpnc.a

libvpnc.a: isakmp-pkt.o math_group.o dh.o
	$(AR) cru $@ $^

isakmp-pkt.o: isakmp-pkt.c isakmp-pkt.h isakmp.h
	$(CC) $(CFLAGS) $(CSTD) $(COPTS) -c -o $@ $<

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CSTD) $(COPTS) -c -o $@ $<

clean:
	rm -rf *.o *.a *.core

.PHONY: all clean
