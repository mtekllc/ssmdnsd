AC_PREREQ([2.69])
m4_define([name], m4_esyscmd([grep -Po '(?<=^name=).*' proj | tr -d '\n']))
m4_define([version], m4_esyscmd([grep -Po '(?<=(^version=)).*' proj | tr -d '\n']))
m4_define([bugs], m4_esyscmd([grep -Po '(?<=(^bugs=)).*' proj | tr -d '\n']))
AC_INIT(m4_defn([name]),m4_defn([version]),m4_defn([bugs]))

AC_CONFIG_HEADERS([src/config.h])
AC_DEFINE([_GNU_SOURCE], [1], [gnu extensions])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wno-error -Wno-portability])

AC_CONFIG_FILES([Makefile ssmdnsd.1])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h fenv.h inttypes.h netinet/in.h stdint.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([inet_ntoa memset socket strerror])
AC_OUTPUT
