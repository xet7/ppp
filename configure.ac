#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE(ppp, 1.0)
AC_CONFIG_SRCDIR([rijndael.h])
#AC_CONFIG_HEADER([config.h])
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_GETLOADAVG
AC_FUNC_MALLOC
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([gethostname gettimeofday memset])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
