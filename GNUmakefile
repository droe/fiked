# fiked - a fake IKE PSK+XAUTH daemon based on vpnc
# Copyright (C) 2005,2009 Daniel Roethlisberger <daniel@roe.ch>
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

PREFIX?=/usr/local
LOCALBASE?=/usr/local
CC?=gcc
CFLAGS?=-g -Wall -pedantic
LDFLAGS?=-g -Wall -pedantic
CSTD=-std=c99
COPTS=-I$(LOCALBASE)/include
LDOPTS=-L$(LOCALBASE)/lib
LIBS=-lgcrypt

ifndef WITHOUT_LIBNET
LIBNET_CFLAGS?=$(shell libnet11-config --cflags || libnet-config --cflags)
LIBNET_LIBS?=$(shell libnet11-config --libs || libnet-config --libs)
CFLAGS+=$(LIBNET_CFLAGS)
LIBS+=$(LIBNET_LIBS)
COPTS+=-DWITH_LIBNET
endif

ifeq ($(shell uname),Linux)
COPTS+=-D_BSD_SOURCE -D_GNU_SOURCE
endif

PGM=fiked
OBJS=mem.o config.o datagram.o send_dgm.o peer_ctx.o results.o log.o ike.o main.o
SUBDIR=vpnc
SUBLIB=lib$(SUBDIR).a

URL=http://www.roe.ch/FakeIKEd
VERSION=$(shell cat VERSION)

all: $(PGM)

$(PGM): $(OBJS) $(SUBLIB)
	$(CC) $(LDFLAGS) $(LDOPTS) -o $@ $^ $(LIBS)

subdir:
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
		CSTD="$(CSTD)" COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" \
		$(MAKE) -C $(SUBDIR) all

$(SUBLIB): subdir
	@ln -sf $(SUBDIR)/$@ $@

main.o: main.c $(SUBDIR)/*.h *.h
	$(CC) $(CFLAGS) $(CSTD) -DVERSION=\"$(VERSION)\" -DURL=\"$(URL)\" \
		$(COPTS) -c -o $@ $<

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CSTD) $(COPTS) -c -o $@ $<

strip: $(PGM)
	strip -g $^

install: strip
	install -o root -g 0 -m 0444 $(PGM).1 $(PREFIX)/man/man1/
	install -o root -g 0 -m 0511 $(PGM) $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/man/man1/$(PGM).1
	rm -f $(PREFIX)/bin/$(PGM)

package: clean
	mkdir $(PGM)-$(VERSION) && \
	tar -c -f - `find . -type f | grep -v svn` \
		| tar -x -C $(PGM)-$(VERSION)/ -f - && \
	tar cvfy $(PGM)-$(VERSION).tar.bz2 $(PGM)-$(VERSION) && \
	rm -r $(PGM)-$(VERSION)

clean:
	rm -rf *.o *.a *.core *.log ChangeLog $(PGM)-$(VERSION).tar.bz2 $(PGM)
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" LIBS="$(LIBS)" \
		$(MAKE) -C $(SUBDIR) clean

.PHONY: all install uninstall package clean subdir
