# IKE MITM for Cisco PSK+XAUTH.
# Copyright (C) 2005, Daniel Roethlisberger <daniel@roe.ch>
# 
# All rights reserved.  This is unpublished work.  Unauthorized use,
# distribution in source or binary form, modified or unmodified, is
# strictly prohibited.
# 
# $Id$

all: isakmp-pkt.o

isakmp-pkt.o: isakmp-pkt.c isakmp-pkt.h isakmp.h
	$(CC) $(CFLAGS) $(CSTD) -c -o $@ $<

clean:
	rm -rf *.o *.core

.PHONY: all clean
