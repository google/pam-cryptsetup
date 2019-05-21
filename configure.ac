AC_PREREQ([2.68])
AC_INIT([pam-cryptsetup], [0.1])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([m4])
# Ignore portability warnings from including GLib TAP test harness macro.
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign])
#AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O

# Checks for libraries.
AM_PROG_AR
LT_INIT
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.32.4])
AC_CHECK_LIB([cryptsetup], [crypt_init], [], [AC_MSG_ERROR([libcryptsetup not found])])
AC_CHECK_LIB([pam], [pam_start], [], [AC_MSG_ERROR([libpam not found])])

# Checks for header files.
AC_CHECK_HEADERS(
    [errno.h fcntl.h stdio.h stdlib.h string.h strings.h sys/mman.h sys/types.h sys/wait.h sysexits.h syslog.h unistd.h],
    [], [AC_MSG_ERROR([missing system headers])])
AC_CHECK_HEADERS(
    [libcryptsetup.h],
    [], [AC_MSG_ERROR([missing libcryptsetup headers])])
AC_CHECK_HEADERS(
    [libdevmapper.h],
    [], [AC_MSG_ERROR([missing libdevmapper headers])])
AC_CHECK_HEADERS(
    [security/pam_ext.h security/pam_modules.h],
    [], [AC_MSG_ERROR([missing libpam headers])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset explicit_bzero])

# Enable GLib TAP testing harness.
GLIB_TESTS

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 testdata/Makefile])
AC_OUTPUT
