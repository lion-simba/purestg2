#***********************************************************************
#
# Makefile for PureSTG authentication stargazer plugin
#
# Copyright (C) 2010-2011 Alexey Osipov <lion-simba@pridelands.ru>
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
#***********************************************************************

PLUGINSDIR = /usr/lib/stg
STGINCS=/usr/include/stargazer
CFLAGS  = -O2 -I$(STGINCS) -I../include -fPIC -DRELEASE -DLINUX
PLUGINNAME = mod_auth_purestg2.so

all: $(PLUGINNAME)

purestg2.o: purestg2.cpp purestg2.h
	$(CC) -c -o purestg2.o $(CFLAGS) purestg2.cpp

$(PLUGINNAME): purestg2.o
	$(CC) -o $(PLUGINNAME) -shared $(CFLAGS) $^

install: all
	install -c -s -m 644 $(PLUGINNAME) $(PLUGINSDIR)/$(PLUGINNAME)

uninstall:
	rm -f $(PLUGINSDIR)/$(PLUGINNAME)

clean:
	rm -f *.o *.so
