###############################################################################
# $Id: Makefile,v 1.9 2007/09/26 14:06:06 faust Exp $
###############################################################################

include ../../../../../Makefile.conf

LIBS = -lstg_common

ifeq ($(OS),linux)
LIBS += -lpthread
endif

ifeq ($(OS),bsd)
LIBS += -lc_r
endif

ifeq ($(OS),bsd5)
LIBS += -lc_r
endif

PROG = mod_auth_purestg2.so

SRCS = ./purestg2.cpp

include ../../Makefile.in

