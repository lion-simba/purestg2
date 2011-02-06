#***********************************************************************
#
# Makefile for PureSTG authentication pppd plugin
#
# Copyright (C) 2010-2011 Alexey Osipov <lion-simba@pridelands.ru>
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
#***********************************************************************

PPPVERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' /usr/include/pppd/patchlevel.h)
LIBDIR = /usr/lib/pppd/$(PPPVERSION)
PPPINCS=/usr/include/pppd
STGINCS=/usr/include/stargazer
CFLAGS  = -O2 -I$(PPPINCS) -I$(STGINCS) -I../include -fPIC -DRELEASE
PLUGINNAME = purestg2.so

all: $(PLUGINNAME)

purestg2.o: purestg2.c
	$(CC) -c -o purestg2.o $(CFLAGS) purestg2.c

pureclient.o: pureclient.c pureclient.h
	$(CC) -c -o pureclient.o $(CFLAGS) pureclient.c

$(PLUGINNAME): purestg2.o pureclient.o
	$(CC) -o $(PLUGINNAME) -shared $(CFLAGS) purestg2.o pureclient.o

install: all
	install -c -s -m 644 $(PLUGINNAME) $(LIBDIR)/$(PLUGINNAME)

uninstall:
	rm -f $(LIBDIR)/$(PLUGINNAME)

clean:
	rm -f *.o *.so
