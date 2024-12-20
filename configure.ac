AC_PREREQ([2.69])
m4_define([name], m4_esyscmd([grep -Po '(?<=^name=).*' proj | tr -d '\n']))
m4_define([version], m4_esyscmd([grep -Po '(?<=(^version=)).*' proj | tr -d '\n']))
m4_define([bugs], m4_esyscmd([grep -Po '(?<=(^bugs=)).*' proj | tr -d '\n']))
AC_INIT(m4_defn([name]),m4_defn([version]),m4_defn([bugs]))

AC_CONFIG_HEADERS([src/config.h])
AC_DEFINE([_GNU_SOURCE], [1], [gnu extensions])

AC_ARG_ENABLE([enable-ipv4-only],
    AS_HELP_STRING([--enable-ipv4-only], [disable ipv6 support]))
AS_IF([test "x$enable_ipv4_only" = "xyes"], [
    AC_DEFINE([DISABLE_IPV6], [1], [ipv6 support disabled])
], [
    AC_DEFINE([DISABLE_IPV6], [0], [ipv6 support enabled])
]
)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wno-error -Wno-portability])

AC_CONFIG_FILES([Makefile ssmdnsd.1])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC

AC_OUTPUT
