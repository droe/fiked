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
CFLAGS?=-g -Wall -pedantic
LDFLAGS?=-g -Wall -pedantic
CSTD=-std=c99
COPTS?=-I/usr/local/include
LDOPTS?=-L/usr/local/lib
LIBS=-lgcrypt -lnet

PGM=fiked
OBJS=config.o datagram.o send_dgm.o peer_ctx.o results.o log.o ike.o main.o
SUBDIR=vpnc
SUBLIB=lib$(SUBDIR).a

REPO=svn://projects.roe.ch/repos/$(PGM)
URL=http://www.roe.ch/FakeIKEd
VERSION=$(shell cat VERSION)

all: $(PGM)

$(PGM): $(OBJS) $(SUBLIB)
	$(CC) $(LDFLAGS) $(LDOPTS) -o $@ $^ $(LIBS)

subdir:
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" LIBS="$(LIBS)" \
		$(MAKE) -C $(SUBDIR) all

$(SUBLIB): subdir
	@ln -sf $(SUBDIR)/$@ $@

main.o: main.c $(SUBDIR)/*.h *.h
	$(CC) $(CFLAGS) $(CSTD) -DVERSION=\"$(VERSION)\" -DURL=\"$(URL)\" \
		$(COPTS) -c -o $@ $<

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CSTD) $(COPTS) -c -o $@ $<

package: clean
	svn -v log $(REPO) > ChangeLog
	mkdir $(PGM)-$(VERSION) && \
	tar -c -f - `find . -type f | grep -v svn | grep -v captures` \
		| tar -x -C $(PGM)-$(VERSION)/ -f - && \
	tar cvfy $(PGM)-$(VERSION).tar.bz2 $(PGM)-$(VERSION) && \
	rm -r $(PGM)-$(VERSION)

clean:
	version=`cat VERSION` && \
	rm -rf *.o *.a *.core *.log ChangeLog $(PGM)-$$version.tar.bz2 $(PGM)
	@CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" CSTD="$(CSTD)" \
		COPTS="$(COPTS)" LDOPTS="$(LDOPTS)" LIBS="$(LIBS)" \
		$(MAKE) -C $(SUBDIR) clean

.PHONY: all package clean subdir
