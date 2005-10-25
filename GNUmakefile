# IKE MITM for Cisco PSK+XAUTH.
# Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
# 
# All rights reserved.  This is unpublished work.  Unauthorized use,
# distribution in source or binary form, modified or unmodified, is
# strictly prohibited.
# 
# $Id$

CC=gcc
CFLAGS?=-g -Wall -pedantic-errors
LDFLAGS?=-g -Wall -pedantic-errors
COPTS=-I/usr/local/include
LDOPTS=-L/usr/local/lib
LIBS=-lgcrypt

PGM=xauth-mitm

CSTD=-std=c99

SUBDIR=vpnc
SUBDIR_OBJS=dh.o isakmp-pkt.o math_group.o

all: $(PGM)

$(PGM): $(SUBDIR_OBJS) datagram.o peer_ctx.o ike.o main.o
	$(CC) $(LDFLAGS) $(LDOPTS) -o $@ $^ $(LIBS)

subdirs:
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" LIBS="$(LIBS)" \
		$(MAKE) -C $(SUBDIR) all

$(SUBDIR_OBJS): subdirs
	@ln -sf $(SUBDIR)/$@ $@

main.o: main.c $(SUBDIR)/isakmp.h $(SUBDIR)/isakmp-pkt.h datagram.h peer_ctx.h ike.h
	$(CC) $(CFLAGS) $(CSTD) $(COPTS) -c -o $@ $<

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CSTD) $(COPTS) -c -o $@ $<

clean:
	rm -rf *.o *.core $(PGM)
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" LIBS="$(LIBS)" \
		$(MAKE) -C $(SUBDIR) clean

.PHONY: all clean subdirs
