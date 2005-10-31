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

CC=gcc
CFLAGS?=-g -Wall -pedantic-errors
LDFLAGS?=-g -Wall -pedantic-errors
CSTD=-std=c99
COPTS=-I/usr/local/include
LDOPTS=-L/usr/local/lib
LIBS=-lgcrypt

PGM=fiked

OBJS=config.o datagram.o peer_ctx.o results.o ike.o main.o

SUBDIR=vpnc
SUBDIR_OBJS=dh.o isakmp-pkt.o math_group.o

all: $(PGM)

$(PGM): $(SUBDIR_OBJS) $(OBJS)
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

package: clean
	version=`cat VERSION` && \
	mkdir $(PGM)-$$version && \
	cp `find . -type f | grep -v svn | grep -v captures` $(PGM)-$$version/ && \
	tar cvfy $(PGM)-$$version.tar.bz2 $(PGM)-$$version && \
	rm -r $(PGM)-$$version

clean:
	version=`cat VERSION` && \
	rm -rf *.o *.core *.log $(PGM)-$$version.tar.bz2 $(PGM)
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" LIBS="$(LIBS)" \
		$(MAKE) -C $(SUBDIR) clean

.PHONY: all package clean subdirs
