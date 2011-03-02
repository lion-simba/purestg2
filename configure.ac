#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([purestg2], [2.1], [simba@lerlan.ru])
AM_INIT_AUTOMAKE([-Wall -Werror gnu])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([include/pureproto.h])
AC_CONFIG_HEADERS([config.h])

AH_TEMPLATE([LINUX], Define if you are using Linux)
AH_TEMPLATE([FREE_BSD], Define if you are using FreeBSD4)
AH_TEMPLATE([FREE_BSD5], Define if you are using FreeBSD5 or greater)

# Determine the operating system
AC_MSG_CHECKING([uname -s for detecting host operating system])
OSNAME=`uname -s`
OSRELEASE=`uname -r | cut -b1`
case "$OSNAME" in
        FreeBSD*)
                dnl FreeBSD
                if [ "x$OSRELEASE" = "x4" ]; then
                	AC_MSG_RESULT(FreeBSD)
                	AC_DEFINE(FREE_BSD)
                else
                	AC_MSG_RESULT(FreeBSD5)
                	AC_DEFINE(FREE_BSD5)
                fi
        ;;
        Linux*)
                dnl Linux
                AC_MSG_RESULT(Linux)
                AC_DEFINE(LINUX)
        ;;
        *)
                AC_MSG_RESULT(no)
        ;;
esac


# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_AWK
AC_PROG_LIBTOOL
AX_PTHREAD(
    [
        AC_DEFINE(HAVE_PTHREAD)
    ],
    [
        AC_MSG_ERROR(pthreads not found or not working)
    ])


# Set pppd and stargazer header directories
AC_ARG_WITH([pppd-headers],
    [AC_HELP_STRING([--with-pppd-headers],
        [where to look for pppd header files, defaults to /usr/include/pppd])],
    [PPPINCS="$withval"],
    [PPPINCS="/usr/include/pppd"])
AC_SUBST([PPPINCS])

AC_ARG_WITH([stg-headers],
    [AC_HELP_STRING([--with-stg-headers],
        [where to look for stargazer header files, defaults to /usr/include/stargazer])],
    [STGINCS="$withval"],
    [STGINCS="/usr/include/stargazer"])
AC_SUBST([STGINCS])

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

CPPFLAGS="$CPPFLAGS -I$PPPINCS -I$STGINCS"

AC_LANG([C])
AC_CHECK_HEADERS([pppd.h fsm.h], [], 
[
    AC_MSG_ERROR(header not found or not useable)
])

AC_CHECK_HEADERS([ipcp.h], [],
[
    AC_MSG_ERROR(header not found or not useable)
],
[
#ifdef HAVE_PPPD_H
#include <pppd.h>
#endif
#ifdef HAVE_FSM_H
#include <fsm.h>
#endif
])

AC_LANG([C++])
AC_CHECK_HEADERS([stg_common.h user.h users.h stg_logger.h base_auth.h], [], 
[
    AC_MSG_ERROR(headers not found or not useable)
])

# Set pppd and stargazer module directories
AC_ARG_WITH([pppd-libdir],
    [AC_HELP_STRING([--with-pppd-libdir],
        [where to install pppd plugin, defaults to /usr/lib/pppd])],
    [pppmoduledir=$withval/$(awk -F '"' '/VERSION/ { print $$2; }' $PPPINCS/patchlevel.h)],
    [pppmoduledir=\${libdir}/pppd/$(awk -F '"' '/VERSION/ { print $$2; }' $PPPINCS/patchlevel.h)])
AC_SUBST([pppmoduledir])

AC_ARG_WITH([stg-libdir],
    [AC_HELP_STRING([--with-stg-libdir],
        [where to install stargazer plugin, defaults to /usr/lib/stg])],
    [stgmoduledir=$withval],
    [stgmoduledir=\${libdir}/stg])
AC_SUBST([stgmoduledir])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_CHECK_FUNCS([inet_ntoa memset socket strerror strtol])

AC_CONFIG_FILES([Makefile
                 pppd/Makefile
                 stargazer/Makefile])
AC_OUTPUT
