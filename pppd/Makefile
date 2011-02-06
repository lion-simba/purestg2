#***********************************************************************
#
# Makefile
#
# Makefile for PureSTG authentication plugin
#
# Copyright (C) 2010 Alexey Osipov <lion-simba@pridelands.ru>
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
#***********************************************************************

VERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' /usr/include/pppd/patchlevel.h)
LIBDIR = /usr/lib/pppd/$(VERSION)/
# CFLAGS  = -g -O2 -I/usr/include/pppd -L/usr/lib/mysql -DMSLANMAN -fPIC -lmysqlclient
# For beta pppd version 2.4.2b3
#CFLAGS  = -g -O2 -I/usr/include/pppd -fPIC -L/usr/lib/mysql -lmysqlclient
# For pppd version 2.4.2 release
CFLAGS  = -O2 -I/usr/include/pppd -fPIC -DRELEASE
#CFLAGS  = -I/usr/include/pppd
all: purestg2.so

purestg2.o: purestg2.c stg_common.h
	gcc -c -o purestg2.o $(CFLAGS) purestg2.c

pureclient.o: pureclient.c pureclient.h stg_common.h
	gcc -c -o pureclient.o $(CFLAGS) pureclient.c

purestg2.so: purestg2.o pureclient.o
	gcc -o purestg2.so -shared $(CFLAGS) purestg2.o pureclient.o

install: all
	install -c -m 4550 ./purestg2.so $(LIBDIR)purestg2.so

clean:
	rm -f *.o *.so
