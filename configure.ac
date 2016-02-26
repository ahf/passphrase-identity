AC_PREREQ([2.59])
AC_INIT([teneo], [0.1.0], [ahf@0x90.dk], [teneo], [])

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])

AC_LANG([C])

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LD

PKG_CHECK_MODULES([SODIUM], [libsodium])

GLIB_TESTS

TENEO_CFLAGS=

PREFERED_CFLAGS="-pedantic -Werror -Wall -Wextra -Wbad-function-cast -Wcast-align -Wcast-qual -Wfloat-equal -Wformat=2 -Wformat-security -Wformat-nonliteral -Winit-self -Winline -Wmissing-prototypes -Wmissing-declarations -Wmissing-format-attribute -Wmissing-noreturn -Wpointer-arith -Wredundant-decls -Wshadow -Wswitch-default -Wunused"

for flag in $PREFERED_CFLAGS; do
    AX_CHECK_COMPILER_FLAGS([$flag], [TENEO_CFLAGS="$TENEO_CFLAGS $flag"],)
done

AC_SUBST([TENEO_CFLAGS])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT
