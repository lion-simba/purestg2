pppmodule_LTLIBRARIES = purestg2.la

purestg2_la_SOURCES = purestg2.c pureclient.c pureclient.h ../include/pureproto.h
purestg2_la_LDFLAGS = -module -avoid-version -shared -s
AM_CPPFLAGS = -I.. -I../include -I$(PPPINCS) -I$(STGINCS)

#install-data-hook:
#	rm -f $(DESTDIR)$(pppmoduledir)/purestg2.la
