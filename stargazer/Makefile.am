stgmodule_LTLIBRARIES = mod_auth_purestg2.la

mod_auth_purestg2_la_SOURCES = purestg2.cpp purestg2.h ../include/pureproto.h
mod_auth_purestg2_la_LDFLAGS = -module -avoid-version -shared -s

AM_CPPFLAGS = -I.. -I$(top_srcdir)/include -I$(STGINCS)

#install-data-hook:
#	rm -f $(DESTDIR)$(stgmoduledir)/mod_auth_purestg2.la
