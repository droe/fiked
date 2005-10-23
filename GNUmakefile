# ISAKMP MITM for Cisco PSK+XAUTH.
# Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
# 
# All rights reserved.  This is unpublished work.  Unauthorized use,
# distribution in source or binary form, modified or unmodified, is
# strictly prohibited.
# 
# $Id$

CC?=gcc
CFLAGS?=-g -Wall -pedantic
LDFLAGS?=-g -Wall -pedantic

PGM=xauth-mitm

CSTD=-std=c99

all: $(PGM)

$(PGM): isakmp-pkt.o datagram.o main.o
	$(CC) $(LDFLAGS) -o $@ $^

isakmp-pkt.o:
	cd isakmp && $(MAKE) $@
	ln -s isakmp/$@ $@

%.o: %.c
	$(CC) $(CFLAGS) $(CSTD) -c -o $@ $<

clean:
	rm -rf *.o *.core $(PGM)
	cd isakmp && $(MAKE) clean

.PHONY: all clean isakmp
