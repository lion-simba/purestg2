pppmodule_LTLIBRARIES = purestg2.la

purestg2_la_SOURCES = purestg2.c pureclient.c pureclient.h ../include/pureproto.h
purestg2_la_LDFLAGS = -module -avoid-version -shared -s $(PTHREAD_LIBS)
purestg2_la_CFLAGS = $(PTHREAD_CFLAGS)
AM_CPPFLAGS = -I.. -I$(top_srcdir)/include -I$(PPPINCS) -I$(STGINCS)

#install-data-hook:
#	rm -f $(DESTDIR)$(pppmoduledir)/purestg2.la
