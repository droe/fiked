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

PGM=xauth-mitm

CSTD=-std=c99

all: $(PGM)

$(PGM): isakmp-pkt.o datagram.o peer_ctx.o ike.o main.o
	$(CC) $(LDFLAGS) -o $@ $^

isakmp-pkt.o:
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		$(MAKE) -C isakmp $@
	ln -s isakmp/$@ $@

main.o: main.c isakmp/isakmp.h isakmp/isakmp-pkt.h datagram.h peer_ctx.h ike.h
	$(CC) $(CFLAGS) $(CSTD) -c -o $@ $<

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CSTD) -c -o $@ $<

clean:
	rm -rf *.o *.core $(PGM)
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		$(MAKE) -C isakmp clean

.PHONY: all clean isakmp
