AC_PREREQ([2.68])
AC_INIT([pam-cryptsetup], [0.1])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_SILENT_RULES([yes])

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
AC_CHECK_LIB([devmapper], [dm_lib_init], [], [AC_MSG_ERROR([libdevmapper not found])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([libpthread not found])])

# Checks for header files.
AC_CHECK_HEADERS(
    [errno.h stdint.h stdlib.h string.h sys/stat.h unistd.h pthread.h],
    [], [AC_MSG_ERROR([missing system headers])])
AC_CHECK_HEADERS(
    [libcryptsetup.h],
    [], [AC_MSG_ERROR([missing libcryptsetup headers])])
AC_CHECK_HEADERS(
    [security/pam_ext.h security/pam_modules.h],
    [], [AC_MSG_ERROR([missing libpam headers])])
AC_CHECK_HEADERS(
    [libdevmapper.h],
    [], [AC_MSG_ERROR([missing libdevmapper headers])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 testdata/Makefile])
AC_OUTPUT
