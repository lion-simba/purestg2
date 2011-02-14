SUBDIRS=pppd stargazer
ACLOCAL_AMFLAGS = -I m4

dist-hook: ChangeLog
 
ChangeLog: configure.ac
	git log --stat --name-only --date=short --abbrev-commit > ChangeLog
